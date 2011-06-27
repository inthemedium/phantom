# this scrip restart all the phantom processes running in tmux
command = ['tmux kill-window -t phantom:phantom']
output = run_command_on_instances(command, instances)
pprint(output)

command = ['! pgrep phantom$',
           'sudo ip address flush dev phantom',
           'tmux new-window -t phantom: -n phantom',
           'tmux clear-history -t phantom:phantom',
           'tmux send-keys -t phantom:phantom \'cd /home/ubuntu/phantom/src/ && sudo ./phantom\' C-m']
output = run_command_on_instances(command, instances)
pprint(output)
