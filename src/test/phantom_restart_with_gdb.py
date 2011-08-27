# this script restart all the phantom processes running in tmux

command = ['! [ -a ~/PERSISTENT_GDB ]',
           '(sudo killall -9 phantom; sudo killall -9 gdb)']

output = run_command_on_instances(command, instances)

command = ['! [ -a ~/PERSISTENT_GDB ]',
           '! pgrep gdb$',
           '! pgrep phantom$',
		       'tmux kill-window -t phantom:phantom',
           'sudo ip address flush dev phantom',
           'tmux new-window -t phantom: -n phantom',
           'tmux clear-history -t phantom:phantom',
           'tmux send-keys -t phantom:phantom \'cd /home/ubuntu/phantom/src/ && sudo gdb ./phantom\' C-m',
           'tmux send-keys -t phantom:phantom \'set print thread-events off\' C-m',
#           'tmux send-keys -t phantom:phantom \'condition 1 want == 0\' C-m',
#           'tmux send-keys -t phantom:phantom \'break diskcache.c:95\' C-m',
           'tmux send-keys -t phantom:phantom \'run\' C-m',
#           'tmux send-keys -t phantom:phantom \'print path->entry_ip\' C-m',
#           'tmux send-keys -t phantom:phantom \'print path->entry_port\' C-m',
#           'tmux send-keys -t phantom:phantom \'c\' C-m']
           'tmux send-keys -t phantom:phantom \'bt\' C-m']
output = run_command_on_instances(command, instances)
pprint(output)
