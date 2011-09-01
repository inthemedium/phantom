# this script restart all the phantom processes running in tmux
command = ['rm -rf ~/tmp || true',
           'cp -r phantom/src ~/tmp']

output = run_command_on_instances(command, instances)

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
           'tmux send-keys -t phantom:phantom \'cd /home/ubuntu/tmp\' C-m',
           'tmux send-keys -t phantom:phantom \'sudo gdb ./phantom\' C-m',
           'tmux send-keys -t phantom:phantom \'set print thread-events off\' C-m',
#           'tmux send-keys -t phantom:phantom \'break kademlia_rpc.c:685\' C-m',
#           'tmux send-keys -t phantom:phantom \'condition 1 want == 0\' C-m',
           'tmux send-keys -t phantom:phantom \'run\' C-m',
#           'tmux send-keys -t phantom:phantom \'print path->entry_ip\' C-m',
#           'tmux send-keys -t phantom:phantom \'print path->entry_port\' C-m',
#           'tmux send-keys -t phantom:phantom \'c\' C-m']
           'tmux send-keys -t phantom:phantom \'bt\' C-m']
output = run_command_on_instances(command, instances)
pprint(output)
