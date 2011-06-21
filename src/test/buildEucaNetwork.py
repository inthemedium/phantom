#!/usr/bin/env python2.7

# The script can be called as follows:
# python buildEucaNetwork.py [num_inst]
# where num_inst is the number of instances to launch, if it is not present the currently running instances will have commands run on them

# In order for this script to work you will need to do the following:
# 1. install boto and paramiko python modules
# 2. generate a key named 'phantom' on eucalyptus and place it at '~/.euca/id_phantom'
# 3. setup euca2ools such that the environment variables 'EC2_URL', 'EC2_ACCESS_KEY', and 'EC2_SECRET_KEY' key are defined
# 4. change the my_id to your eucalpytus username
# 5. run it on the secclound!

import pdb
import os
import sys
import time
import boto
import boto.ec2
import paramiko
from pprint import pprint
from threading import Thread

# Global vars 
img_id = "emi-3F101642"
img_username = "ubuntu"

key_name = "phantom"
key_filename = os.path.expanduser('~/.euca/id_' + key_name)

ec2_inside_url = "http://192.168.48.91:8773/services/Eucalyptus"
inside_access = None

# hard-coded for now
my_id = "inthemedium"

# # official repo
# fetch_src_cmd = 'git svn clone -s http://phantom.googlecode.com/svn phantom'
# my repo
fetch_src_cmd = 'git clone git@github.com:inthemedium/phantom.git'

class CommandInstance(Thread):
    def __init__ (self, instance):
        Thread.__init__(self)
        self.instance = instance
        self.client = paramiko.SSHClient()
        self.hostname = instance.dns_name
        self.ssh_port = 22
        if not inside_access:
            self.hostname = "128.111.48.6"
            self.ssh_port = int('48' + self.instance.dns_name.split('.')[3].zfill(3))
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.command = ""
        self.results = []

    def set_command(self, command_list, file_tuples):
        self.command_list = command_list
        self.file_tuples = file_tuples

    def run(self):
        self.client.connect(self.hostname, 
                            self.ssh_port, 
                            img_username, 
                            key_filename=key_filename)
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
        if chan.recv_exit_status() != 0:
            print "\t chain of commands"
            print "\t %s" % cmd_str
            print "\t had a non-zero return code" 
        stdout = chan.makefile('rb')
        self.results = stdout.readlines()
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

        print "-----Start single instance output-----"
        for line in thread.results:
            print "\t", line,

    return results

def main():
    ep_hostname = os.environ['EC2_URL'].split('/')[2].split(':')[0]
    ep_port = int(os.environ['EC2_URL'].split('/')[2].split(':')[1])
    access_key = os.environ['EC2_ACCESS_KEY']
    secret_key = os.environ['EC2_SECRET_KEY']

    global inside_access
    if os.environ['EC2_URL'] == ec2_inside_url:
        inside_access = True
    else:
        inside_access = False

    try:
        total_insts = int(sys.argv[1]) 
    except (ValueError, IndexError):
        total_insts = 0

    region = boto.ec2.regioninfo.RegionInfo(name="eucalpytus", endpoint=ep_hostname)
    connection = boto.connect_ec2(aws_access_key_id=access_key,
                                  aws_secret_access_key=secret_key,
                                  is_secure=False,
                                  region=region,
                                  port=ep_port,
                                  path="/services/Eucalyptus")

    # this method actually returns reservation objects rather than instance objects
    all_reservations = connection.get_all_instances()
    images = connection.get_all_images()
    # kernels = connection.get_all_kernels()
    keys = connection.get_all_key_pairs()
    instances = None
    # NFS server
    server_inst = None
    server_set = None

    if total_insts > 0:
        for img in images:
            if img.id == img_id:
                pub_res = img.run(min_count=total_insts,
                                  max_count=total_insts,
                                  instance_type='m1.small',
                                  key_name=key_name,
                                  addressing_type='public')

                instances = frozenset(pub_res.instances)

        running_insts = 0

        sys.stdout.write("Waiting for instances. This *will* take a few minutes")
        while running_insts != total_insts:
            sys.stdout.write(".")
            sys.stdout.flush()
            running_insts = 0

            for inst in instances:
                inst.update()
                if inst.state == "running":
                    running_insts += 1

            time.sleep(15)

        print
        print("Setting up instances. This will be another few minutes.")

        # marking which instance will be the NFS server
        for inst in instances:
            if inst.ami_launch_index == '0':
                inst.tags = {'server':True}
                server_inst = inst
                server_set = frozenset([server_inst])
            else:
                inst.tags = {'server':False}

        file_tuples = [('./server.patch', 'server.patch'), 
                       ('./phantom.patch', 'phantom.patch'),
                       (key_filename, '.ssh/id_rsa')]
        command = ['sudo apt-get update',
                   'sudo apt-get -y install git-svn gcc libssl-dev libxml2-dev libprotobuf-c0-dev protobuf-c-compiler nfs-kernel-server',
                   'chmod 600 ~/.ssh/id_rsa',
                   'cd /',
                   'sudo patch -p1 < ~/server.patch',
                   'cd',
                   fetch_src_cmd,
                   'mv phantom.patch phantom/',
                   'cd phantom',
                   'patch -p1 < phantom.patch',
                   'cd protos',
                   './generate_protos.sh',
                   'cd ../src',
                   'make',
                   'cd ~/phantom/scripts',
                   'make',
                   'sudo useradd phantom_user',
                   'sudo bash ./phantom.sh start',
                   'sudo service idmapd --full-restart',
                   'sudo service statd --full-restart',
                   'sudo service nfs-kernel-server --full-restart']
        run_command_on_instances(command, server_set, file_tuples)

        file_tuples = [('./client.patch', 'client.patch')]
        command = ['sudo apt-get -y install nfs-common libprotobuf-c0',
                   'sudo useradd phantom_user',
                   'cd /etc',
                   'sudo patch -p1 < ~/client.patch',
                   'sudo service idmapd --full-restart',
                   'sudo service statd --full-restart', 
                   'sudo modprobe nfs',
                   'cd',
                   'mkdir phantom',
                   'sudo mount -t nfs4 ' + server_inst.private_dns_name + ':/ /home/ubuntu/phantom']
        run_command_on_instances(command, instances - server_set, file_tuples)

        # get hostnames to create network to seed KAD
        command = ["hostname"]
        results = run_command_on_instances(command, instances)
        hostnames = ""
        for inst in results:
            hostnames = inst[0].split('\n')[0] + " " + hostnames

        command = ['cd phantom/src/test',
                   'rm -f *.pem *.list *.conf *.data',
                   './gencerts.sh "' + hostnames + '"',
                   './genkadnodes-list.sh']
        run_command_on_instances(command, server_set)

        command = ['echo "screen\n' 
                   + 'stuff \'cd /home/ubuntu/phantom/src/ && sudo ./phantomd && sudo ./phantom\015\'" > phantom.screenrc',
                   'screen -d -m -c phantom.screenrc']
        run_command_on_instances(command, instances)

    else:
        # find all the already running instances
        tmp_insts = []
        for res in all_reservations:
            if res.owner_id == my_id:
                for inst in res.instances:
                    if inst.key_name == key_name:
                        tmp_insts.append(inst) 

        instances = frozenset(tmp_insts)

    # drop to a shell when everything is done
    while True:
        cmd = raw_input("specify a command to run on all instances (remember, shell state is not saved between commands) \n# ")
        if cmd == "quit" or cmd == "exit":
            break
        
        run_command_on_instances([cmd], instances)


# # stop all instances
# for i in instances:
#     pprint( i.__dict__)
#     i.stop()

if __name__ == '__main__':
    main()

# pdb.set_trace()
