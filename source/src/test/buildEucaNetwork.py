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

# hard-coded for now
my_id = "inthemedium"

class CommandInstance(Thread):
    def __init__ (self, instance):
        Thread.__init__(self)
        self.instance = instance
        self.ssh = paramiko.SSHClient()
        ssh_port = int('48' + self.instance.dns_name.split('.')[3].zfill(3))
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect('128.111.48.6', 
                    ssh_port, 
                    img_username, 
                    key_filename=key_filename)
        self.ftp = self.ssh.open_sftp()
        self.command = ""
        self.results = []

    def set_command(self, command, file_tuples):
        self.command = command
        self.file_tuples = file_tuples

    def run(self):
        for src, dest in self.file_tuples:
            self.ftp.put(src, dest)
        stdin, stdout, stderr = self.ssh.exec_command(self.command)
        self. results = stdout.readlines()
        self.ftp.close()
        self.ssh.close()
        # print stdout.readlines()

def run_command_on_instances(command, instances, file_tuples=()):
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
    ep_hostname = os.environ['EC2_URL'].split('/')[2].split(':')[0]
    ep_port = int(os.environ['EC2_URL'].split('/')[2].split(':')[1])
    access_key = os.environ['EC2_ACCESS_KEY']
    secret_key = os.environ['EC2_SECRET_KEY']

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
    instances = frozenset()
    # NFS server
    server_inst = None
    server_set = frozenset()

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
    else:
        # find all the already running instances
        for res in all_reservations:
            if res.owner_id == my_id:
                for inst in res.instances:
                    if inst.key_name == key_name:
                        instances.append(inst) 

    # marking which instance will be the NFS server
    for inst in instances:
        if inst.ami_launch_index == '0':
            inst.tags = {'server':True}
            server_inst = inst
            server_set = frozenset(server_inst)
        else:
            inst.tags = {'server':False}

    print("Setting up instances. This will be another few minutes.")

    file_tuples = (('./server.patch', 'server.patch'), 
                   ('./phantom.patch', 'phantom/phantom.patch'))
    command = """sudo apt-get -y install git-svn gcc libssl-dev libxml2-dev libprotobuf-c0-dev protobuf-c-compiler nfs-kernel-server &&\
    git svn clone -s http://phantom.googlecode.com/svn phantom &&\
    cd phantom &&\
    patch -p1 < phantom.patch &&\
    cd source/protos &&\
    ./generate_protos.sh &&\
    cd ../src &&\
    make &&\
    cd ~/phantom/source/scripts &&\
    make &&\
    sudo useradd phantom_user &&\
    sudo bash ./phantom.sh start &&\
    cd /etc &&\
    sudo patch -p1 < ~/server.patch &&\
    sudo service idmapd --full-restart &&\
    sudo service statd --full-restart &&\
    sudo service nfs-kernel-server --full-restart"""
    run_command_on_instances(command, server_set, file_tuples)

    file_tuples = (('./client.patch', 'client.patch'))
    command = """sudo apt-get -y install nfs-common libprotobuf-c0 &&\
    sudo useradd phantom_user &&\
    cd /etc &&\
    sudo patch -p1 < ~/client.patch &&\
    sudo service idmapd --full-restart &&\
    sudo service statd --full-restart &&\ 
    sudo modprobe nfs &&\
    cd &&\
    mkdir phantom &&\
    sudo mount -t nfs4 """ + server_inst.private_dns_name + """:/ /home/ubuntu/phantom"""
    run_command_on_instances(command, instances - server_set, file_tuples)

    # get hostnames to create network to seed KAD
    command = "hostname"
    results = run_command_on_instances(command, instances)

    hostnames = ""
    for inst in results:
        hostnames = inst.results[0].split('\n')[0] + " " + hostnames

    command = """cd phantom/source/src/test &&\
    rm *.pem *.list *.conf *.data &&\
    ./gencerts.sh '""" + hostnames + """' &&\
    ./genkadnodes-list.sh"""
    run_command_on_instances(command, server_set)


# pdb.set_trace()


# # stop all instances
# for i in instances:
#     pprint( i.__dict__)
#     i.stop()

if __name__ == '__main__':
    main()
