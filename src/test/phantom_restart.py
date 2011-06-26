# this scrip restart all the phantom processes running in tmux
command = ['tmux send-keys -t phantom C-c']
output = run_command_on_instances(command, instances)
pprint(output)

command = ['sudo ip address flush dev phantom',
           'tmux send-keys -t phantom \'cd /home/ubuntu/phantom/src/ && sudo ./phantom\' C-m']
output = run_command_on_instances(command, instances)
pprint(output)
