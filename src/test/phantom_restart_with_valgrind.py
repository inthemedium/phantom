# this script restart all the phantom processes running in tmux

command = ['tmux kill-window -t phantom:phantom',
           'sudo ip address flush dev phantom',
           'tmux new-window -t phantom: -n phantom',
           'tmux clear-history -t phantom:phantom',
           'sleep 10',
					 'while [ "0" = "`ps aux | grep -v -e grep | grep valgrind.bin > /dev/null; echo $?`" ]; do sleep 10; done'
					 ]

output = run_command_on_instances(command, instances)

command = ['tmux send-keys -t phantom:phantom \'cd /home/ubuntu/phantom/src/ && sudo valgrind --leak-check=yes --error-limit=no --suppressions=test/valgrind.supp ./phantom\' C-m']
output = run_command_on_instances(command, instances)
pprint(output)
