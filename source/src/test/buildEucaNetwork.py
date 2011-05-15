#!/usr/bin/env python2.6

import pdb
import os
import sys
import time
import boto
import boto.ec2
import paramiko
from pprint import pprint
from threading import Thread
import Queue

class SetupClient(Thread):
    def __init__ (self, ssh, command, results):
        Thread.__init__(self)
        self.ssh = ssh
        self.command = command
        self.results = results

    def run(self):
        stdin, stdout, stderr = self.ssh.exec_command(self.command)
        #print stdout.readlines()
        self.ssh.close()
        results.put(stdout.readlines())


ep_hostname = os.environ['EC2_URL'].split('/')[2].split(':')[0]
ep_port = int(os.environ['EC2_URL'].split('/')[2].split(':')[1])
access_key = os.environ['EC2_ACCESS_KEY']
secret_key = os.environ['EC2_SECRET_KEY']

img_id = "emi-3F101642"
try:
    total_insts = int(sys.argv[1]) 
except (ValueError, IndexError):
    total_insts = 0

key_name = "phantom"
key_filename = os.path.expanduser('~/.euca/id_' + key_name)


# hard-coded for now
my_id = "inthemedium"

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
#kernels = connection.get_all_kernels()
keys = connection.get_all_key_pairs()
instances = []

if total_insts > 0:
    for img in images:
        if img.id == img_id:
            pub_res = img.run(min_count=1,
                              max_count=1,
                              instance_type='m1.small',
                              key_name=key_name,
                              addressing_type='public')

            for inst in pub_res.instances:
                inst.tags = {'public':True}
                instances.append(inst)

            # for now we need to do this because there aren't enough public IPs
            priv_res = img.run(min_count=total_insts - 1, 
                               max_count=total_insts - 1, 
                               instance_type='m1.small', 
                               key_name=key_name, 
                               addressing_type='private')

            for inst in priv_res.instances:
                inst.tags = {'public':False}
                instances.append(inst)
    
    running_insts = 0

    sys.stdout.write("Waiting for instances. This *will* take a few minutes")
    while running_insts != total_insts:
        sys.stdout.write(".")
        sys.stdout.flush()
        running_insts = 0

        for inst in instances:
            # the update erases tags because eucalpytus doesn't support tags yet
            tag_store = inst.tags
            inst.update()
            # tags are re-applied here
            inst.tags = tag_store
            if inst.state == "running":
                running_insts += 1

        time.sleep(15)

    print
else:
    # find all the already running instances
    for res in all_reservations:
        if res.owner_id == my_id:
            for inst in res.instances:
                # if eucalyptus supported tags this wouldn't be nessesary
                # seccloud specific!
                if inst.dns_name[0:3] == '192':
                    inst.tags = {'public':True}
                else:
                    inst.tags = {'public':False}
                
                if inst.key_name == key_name:
                    instances.append(inst) 

pdb.set_trace()
print("Setting up instances. This will be another few minutes.")        
ssh = paramiko.SSHClient()
ssh_port = '48xxx'
for inst in instances:
    if inst.tags['public']:
        # seccloud specific!
        ssh_port = int('48' + inst.dns_name.split('.')[3].zfill(3))
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect('128.111.48.6', 
                    ssh_port, 
                    'ubuntu', 
                    key_filename=key_filename)
        ftp = ssh.open_sftp()
        ftp.put(key_filename, '.ssh/id_rsa')
        ftp.chmod('.ssh/id_rsa', int(0o600))
        stdin, stdout, stderr = ssh.exec_command("sudo apt-get -y install git-svn gcc libssl-dev libxml2-dev libprotobuf-c0-dev protobuf-c-compiler nfs-kernel-server") 
        print stdout.readlines()

        stdin, stdout, stderr = ssh.exec_command("git svn clone -s http://phantom.googlecode.com/svn phantom") 
        print stdout.readlines()

        stdin, stdout, stderr = ssh.exec_command("""cd phantom/source/protos &&\
        ./generate_protos.sh &&\
        cd ../src &&\
        make""")
        print stdout.readlines()

        ftp.put('./change_tunnel_path.patch', 'phantom/source/scripts/change_tunnel_path.patch')
        stdin, stdout, stderr = ssh.exec_command("""cd phantom/source/scripts &&\ 
        patch phantom.sh change_tunnel_path.patch &&\
        make &&\
        sudo useradd phantom_user &&\
        sudo bash ./phantom.sh start""")
        print stdout.readlines()

        ftp.put('./server.patch', 'server.patch')
        ftp.put('./client.patch', 'client.patch')
        stdin, stdout, stderr = ssh.exec_command("""cd /etc &&\
        sudo patch -p1 < ~/server.patch &&\
        sudo service idmapd --full-restart &&\
        sudo service statd --full-restart &&\
        sudo service nfs-kernel-server --full-restart""")
        print stdout.readlines()
        ftp.close()
        ssh.close()


ssh_threads = []
results = Queue.Queue()
for inst in instances:
    if not inst.tags['public']:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect('128.111.48.6', 
                    ssh_port, 
                    'ubuntu', 
                    key_filename=key_filename)

        command = """scp -o 'StrictHostKeyChecking no' client.patch """ + inst.dns_name + """: && ssh -o 'StrictHostKeyChecking no' """ + inst.dns_name + """ 'sudo apt-get -y install nfs-common libprotobuf-c0 && sudo useradd phantom_user && cd /etc && sudo patch -p1 < ~/client.patch && sudo service idmapd --full-restart && sudo service statd --full-restart && sudo modprobe nfs && cd && mkdir phantom && sudo mount phantom'"""
        current = SetupClient(ssh, command, results)
        ssh_threads.append(current)
        current.start()

for thread in ssh_threads:
    thread.join()
    
foo = "asfasf"
while foo != None:
    foo = results.get()
    print foo


#pdb.set_trace()
# stop all instances
# for i in instances:
#     pprint( i.__dict__)
#     i.stop()
