#!/usr/bin/env python2.7

# The script can be called as follows:
# python buildEucaNetwork.py [num_inst]
# where num_inst is the number of instances to launch, if it is not present the currently running instances will have commands run on them

# In order for this script to work you will need to do the following:
# 1. install boto, paramiko, and (optional) ipython python modules (debian based distros: apt-get install python-boto python-paramiko ipython)
# 2. generate a key named 'phantom' on eucalyptus and place it at '~/.euca/id_phantom'
# 3. setup euca2ools such that the environment variables 'EC2_URL', 'EC2_ACCESS_KEY', and 'EC2_SECRET_KEY' key are defined
# 4. change the my_id to your eucalpytus username
# 5. run it on the secclound!
# 6. add aws ssh key to github

# TODO use tags when they are implemented with eucalyptus

import os
import sys
import time
import boto
import boto.ec2
import paramiko
import socket
from pprint import pprint
from threading import Thread
import readline

# Global vars

# needs to have a EBS with t1.micro
img_id = "ami-aef607c7"
img_username = "root"

key_name = "amazonkey"
key_filename = os.path.expanduser('~/.ssh/' + key_name)

ec2_inside_url = ""
inside_access = None

# public elastic ip address for the nfs server instance
nfs_server_eip = '192.168.48.3'

# hard-coded for now
my_id = "inthemedium"

# # official repo
# fetch_src_cmd = 'git svn clone -s http://phantom.googlecode.com/svn phantom'
# my repo
fetch_src_cmd = 'git clone git@github.com:inthemedium/phantom.git'

# utility class
class Bunch(dict):
    def __init__(self, **kw):
        dict.__init__(self, kw)
        self.__dict__ = self

    def __getstate__(self):
        return self

    def __setstate__(self, state):
        self.update(state)
        self.__dict__ = self

class CommandInstance(Thread):
    def __init__ (self, instance):
        Thread.__init__(self)
        self.instance = instance
        self.client = paramiko.SSHClient()
        self.hostname = instance.public_dns_name
        self.hostname_prv = instance.private_dns_name
        self.ssh_port = 22
        # if not inside_access:
        #     self.hostname = "128.111.48.6"
        #     self.ssh_port = int('48' + self.instance.dns_name.split('.')[3].zfill(3))
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.command = ""
        self.results = Bunch()

    def set_command(self, command_list, file_tuples):
        self.command_list = command_list
        self.file_tuples = file_tuples

    def run(self):
        while True:
            try:
                self.client.connect(self.hostname,
                                    self.ssh_port,
                                    img_username,
                                    key_filename=key_filename)
                break
            except socket.error:
                if inside_access:
                    print "trying again with private dns name"
                    self.hostname = self.instance.private_dns_name
                    self.client.connect(self.hostname,
                                        self.ssh_port,
                                        img_username,
                                        key_filename=key_filename)
                else:
                    print "connection failed to", self.hostname,\
                          "port", self.ssh_port
                    time.sleep(15)
        ftp = self.client.open_sftp()
        for src, dest in self.file_tuples:
            ftp.put(src, dest)

        cmd_str = ""

        chan = self.client.get_transport().open_session()
        chan.set_combine_stderr(True)
        for command in self.command_list:
            if cmd_str == "":
                cmd_str = command
            else:
                cmd_str = cmd_str + " && " + command

        chan.exec_command(cmd_str)

        # prepare results
        stdout = chan.makefile('rb')
        self.results.command = cmd_str
        self.results.exit_status = chan.recv_exit_status()
        self.results.hostname = self.instance.dns_name
        self.results.hostname_prv = self.hostname_prv
        self.results.instance = self.instance
        self.results.output = stdout.readlines()
        ftp.close()
        self.client.close()

def run_command_on_instances(command, instances, file_tuples=[]):
    cmd_inst_threads = []
    for inst in instances:
        current = CommandInstance(inst)
        current.set_command(command, file_tuples)
        cmd_inst_threads.append(current)
        current.start()

    results = []
    for thread in cmd_inst_threads:
        thread.join()
        results.append(thread.results)

    return results

def main():
    # ep_hostname = os.environ['EC2_URL'].split('/')[2].split(':')[0]
    # ep_port = int(os.environ['EC2_URL'].split('/')[2].split(':')[1])
    # access_key = os.environ['EC2_ACCESS_KEY']
    # secret_key = os.environ['EC2_SECRET_KEY']
    ep_hostname = "us-east-1.ec2.amazonaws.com"
    ep_port = 443
    access_key = os.environ['AWS_ACCESS_KEY_ID']
    secret_key = os.environ['AWS_SECRET_ACCESS_KEY']
    instance_type = "t1.micro"

    global inside_access
    if os.environ['EC2_URL'] == ec2_inside_url:
        inside_access = True
    else:
        inside_access = False

    try:
        total_insts = int(sys.argv[1])
    except (ValueError, IndexError):
        total_insts = 0

    region = boto.ec2.regioninfo.RegionInfo(name="us-east-1", endpoint=ep_hostname)
    # connection = boto.connect_ec2(aws_access_key_id=access_key,
    #                               aws_secret_access_key=secret_key,
    #                               is_secure=True,
    #                               region=region,
    #                               port=ep_port,
    #                               path="/")
    target_region = "us-east-1"
    regions = boto.ec2.regions()
    connection = None
    for region in regions:
        if region.name == target_region:
            connection = region.connect()
    # connection = boto.connect_ec2(region=region)

    # this method actually returns reservation objects rather than instance objects
    all_reservations = []
    for res in connection.get_all_instances():
        all_reservations.append(res)
        for inst in res.instances:
            if inst.state != "running":
                all_reservations.pop()
                break
    img = connection.get_all_images([img_id])[0]
    # kernels = connection.get_all_kernels()
    keys = connection.get_all_key_pairs()
    instances = None
    # NFS server
    server_inst = None
    server_set = None

    if total_insts > 0:
        pub_res = img.run(min_count=total_insts,
                          max_count=total_insts,
                          instance_type=instance_type,
                          key_name=key_name)
                          # addressing_type='public')

        instances = frozenset(pub_res.instances)

        running_insts = 0

        sys.stdout.write("Waiting for instances. This *will* take a few minutes")
        while running_insts != total_insts:
            sys.stdout.write(".")
            sys.stdout.flush()
            running_insts = 0

            for inst in instances:
                try:
                    inst.update()
                except boto.exception.EC2ResponseError:
                    print "received an error in the request!"
                    break

                if inst.state == "running":
                    running_insts += 1

            time.sleep(15)
        # mark which instance will be the NFS server
        for inst in instances:
            if inst.ami_launch_index == '0':
                # change the public ip of the server
                # for a in connection.get_all_addresses():
                #     if a.public_ip == nfs_server_eip:
                #         inst.use_ip(a.public_ip)
                #         # should be:
                #         # while inst.ip_address != a.public_ip:
                #         # but eucalyptus doesn't properly fill the instance obj
                #         while inst.public_dns_name != a.public_ip:
                #             sys.stdout.write(".")
                #             sys.stdout.flush()

                #             inst.update()
                #             time.sleep(1)
                inst.tags = {'server':True}
                server_inst = inst
                server_set = frozenset([server_inst])
            else:
                inst.tags = {'server':False}


        print
        print("Setting up instances. This will be another few minutes.")

        # import pdb; pdb.set_trace()
        # install development tools on all instances
        file_tuples = [('protobuf-c_0.15-1_amd64.deb', 'protobuf-c_0.15-1_amd64.deb')]
        command = ['while true; do sleep 10; sudo apt-get -y update && break; done',
                   'while true; do sleep 10; sudo apt-get -y install git-svn gcc libssl-dev libxml2-dev gdb valgrind clang protobuf-c-compiler libprotobuf-c0-dev && break; done',
                   'while true; do sleep 10; sudo apt-get -y remove libprotobuf-c0-dev && break; done',
                   'while true; do sleep 10; sudo dpkg -i *.deb  && break; done']
        pprint(run_command_on_instances(command, instances, file_tuples))

        # configure easier ssh for nodes and needed to download/upload github source
        file_tuples = [('./home.patch', 'home.patch'),
                       (key_filename, '.ssh/id_rsa')]
        command = ['chmod 600 ~/.ssh/id_rsa',
                   'patch -p1 < home.patch']
        pprint(run_command_on_instances(command, instances, file_tuples))

        # for /etc/exports
        nfs_options = '(rw,fsid=0,insecure,sync)'
        nfs_hosts = '"'
        for inst in instances:
            nfs_hosts = nfs_hosts + ' ' + inst.private_ip_address + nfs_options
        nfs_hosts = nfs_hosts + '"'

        # configure the nfs server
        file_tuples = [('./server.patch', 'server.patch')]
        command = ['while true; do sleep 10; sudo apt-get -y install nfs-kernel-server  && break; done',
                   'cd /',
                   'sudo patch -p1 < ~/server.patch',
                   'sudo sh -c \'echo ~/phantom' + nfs_hosts + '>> /etc/exports\'',
                   'sudo service idmapd --full-restart',
                   'sudo service statd --full-restart',
                   'sudo service nfs-kernel-server --full-restart']
        pprint(run_command_on_instances(command, server_set, file_tuples))

        # build the phantom source
        command = [fetch_src_cmd,
                   'cd phantom',
                   'cd protos',
                   './generate_protos.sh',
                   'cd ../scripts',
                   'make',
                   'cd ../src',
                   'make']
        pprint(run_command_on_instances(command, server_set, file_tuples))

        # configure and mount the nfs share
        file_tuples = [('./client.patch', 'client.patch')]
        command = ['while true; do sleep 10; sudo apt-get -y install nfs-common  && break; done',
                   'cd /etc',
                   'sudo patch -p1 < ~/client.patch',
                   'sudo service idmapd --full-restart',
                   'sudo service statd --full-restart',
                   'sudo modprobe nfs',
                   'cd',
                   'mkdir phantom',
                   'sudo mount -t nfs4 ' + server_inst.private_ip_address + ':/ ~/phantom']
        pprint(run_command_on_instances(command, instances - server_set, file_tuples))

        # get hostnames to create network to seed KAD
        command = ["hostname"]
        results = run_command_on_instances(command, instances)
        hostnames = ""
        for inst in results:
            hostnames = inst.output[0].split('\n')[0] + " " + hostnames


        # generate certs and kad info
        command = ['cd phantom/src/test',
                   'rm -f *.pem *.list *.conf *.data',
                   './gencerts.sh "' + hostnames + '"',
                   './genkadnodes-list.sh']
        pprint(run_command_on_instances(command, server_set))

        # screen is just too hard to deal with, install tmux with the features we need (tmux in 10.04 is too outdated)
        # change this to a simple apt-get install tmux with >= 11.10
        command = ['wget http://sourceforge.net/projects/tmux/files/tmux/tmux-1.4/tmux-1.4.tar.gz',
                   'cd phantom',
                   'tar xvzf ../tmux-1.4.tar.gz']
        pprint(run_command_on_instances(command, server_set))

        command = ['while true; do sleep 10; sudo apt-get -y install libncurses5-dev libevent-dev && break; done',
                   'cp -r phantom/tmux-1.4 ./',
                   'cd tmux-1.4',
                   './configure',
                   'make',
                   'sudo make install']
        pprint(run_command_on_instances(command, instances))

        command = ['rm -rf phantom/tmux-1.4']
        pprint(run_command_on_instances(command, server_set))

        # bring up tun interface and then phantom in a tmux session
        command = ['cd ~/phantom/scripts',
                   'sudo useradd phantom_user',
                   'sudo bash ./phantom.sh start',
                   'cd',
                   'tmux new-session -d -s phantom -n phantom',
                   'tmux new-window -t phantom: -n misc',
                   'tmux send-keys -t phantom:phantom \'cd ~/phantom/src/ && sudo ./phantomd && sudo ./phantom\' C-m',
                   'tmux bind-key C-b last-window']
        pprint(run_command_on_instances(command, instances))

    else:
        # find all the already running instances
        tmp_insts = []
        for res in all_reservations:
            # if res.owner_id == my_id:
                for inst in res.instances:
                    if inst.state == "terminated":
                        continue
                    if inst.key_name == key_name:
                        if inst.ami_launch_index == '0':
                            inst.tags = {'server':True}
                            server_inst = inst
                            server_set = frozenset([server_inst])
                        else:
                            inst.tags = {'server':False}
                        tmp_insts.append(inst)

        instances = frozenset(tmp_insts)

    # drop to a shell when everything is done
    while True:
        cmd = raw_input("specify a command to run on all instances (remember, shell state is not saved between commands) \n# ")
        if cmd == "quit" or cmd == "exit":
            break

        results = run_command_on_instances([cmd], instances)
        pprint(results)
        if raw_input('run ipython with results? (y/n) ') == 'y':

            # run embedded ipython shell on results
            from IPython.Shell import IPShellEmbed

            ipshell = IPShellEmbed()
            ipshell()


# # stop all instances
# for i in instances:
#     pprint( i.__dict__)
#     i.stop()

if __name__ == '__main__':
    main()

# import pdb; pdb.set_trace()
