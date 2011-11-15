# this script restart all the phantom processes running in tmux

instances_in_sync = False
while not instances_in_sync:
    command = ['stat phantom/src/phantom',
               'md5sum -c <(echo "' + md5sum + '")']
    output = run_command_on_instances(command, instances)
    instances_in_sync = True
    for i in output:
        if i.exit_status != 0:
            pprint("instance " + i.hostname + " not in sync")
            pprint(i)
            instances_in_sync = False
            time.sleep(15)
            break

command = ['rm -rf ~/tmp || true',
           'cp -r phantom/src ~/tmp'
          ]

output = run_command_on_instances(command, instances)

command = ['! [ -a ~/PERSISTENT_GDB ]',
           '(sudo killall -9 phantom; sudo killall -9 gdb)',
           'sudo pkill -9 memcheck-amd64',
					 'while [ "0" = "`pgrep memcheck-amd64 > /dev/null; echo $?`" ]; do sleep 1; done'
					 ]

output = run_command_on_instances(command, instances)

command = ['tmux kill-window -t phantom:phantom',
           'sudo ip address flush dev phantom',
           'tmux new-window -t phantom: -n phantom',
           'tmux clear-history -t phantom:phantom',
           'tmux send-keys -t phantom:phantom \'cd ~/tmp\' C-m',
           'tmux send-keys -t phantom:phantom \'sudo valgrind --leak-check=yes --error-limit=no --suppressions=test/valgrind.supp ./phantom\' C-m'
					 ]
output = run_command_on_instances(command, instances)
pprint(output)
