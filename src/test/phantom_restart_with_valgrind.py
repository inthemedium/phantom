# this script restart all the phantom processes running in tmux

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
           'tmux send-keys -t phantom:phantom \'cd /home/ubuntu/tmp\' C-m',
           'tmux send-keys -t phantom:phantom \'sudo valgrind --leak-check=yes --error-limit=no --suppressions=test/valgrind.supp ./phantom\' C-m'
					 ]
output = run_command_on_instances(command, instances)
pprint(output)
