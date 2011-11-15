# this script restart all the phantom processes running in tmux
command = ['md5sum phantom/src/phantom']

output = run_command_on_instances(command, server_set)
md5sum = output[0].output[0].strip()
pprint(md5sum)

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

command = ['! [ -a ~/PERSISTENT_GDB ]',
           '(sudo killall -9 phantom; sudo killall -9 gdb)',
           'sudo pkill -9 memcheck-amd64',
           'while [ "0" = "`pgrep memcheck-amd64 > /dev/null; echo $?`" ]; do sleep 1; done'
           ]

output = run_command_on_instances(command, instances)
command = ['! [ -a ~/PERSISTENT_GDB ]',
           '! pgrep gdb$',
           '! pgrep phantom$',
           'tmux kill-window -t phantom:phantom',
           'sudo ip address flush dev phantom',
           'tmux new-window -t phantom: -n phantom',
           'tmux clear-history -t phantom:phantom',
           'tmux send-keys -t phantom:phantom \'cd ~/phantom/src\' C-m',
           'tmux send-keys -t phantom:phantom \'sudo gdb ./phantom\' C-m',
           'tmux send-keys -t phantom:phantom \'set print thread-events off\' C-m',
#           'tmux send-keys -t phantom:phantom \'break server.c:930\' C-m',
#           'tmux send-keys -t phantom:phantom \'condition 1 want == 0\' C-m',
           'tmux send-keys -t phantom:phantom \'run\' C-m',
#           'tmux send-keys -t phantom:phantom \'print path->entry_ip\' C-m',
#           'tmux send-keys -t phantom:phantom \'print path->entry_port\' C-m',
#           'tmux send-keys -t phantom:phantom \'c\' C-m']
           'tmux send-keys -t phantom:phantom \'bt\' C-m']
output = run_command_on_instances(command, instances)
pprint(output)
