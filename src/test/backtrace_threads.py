command = []
command.append("tmux send-keys -t phantom:phantom C-c")
for i in xrange(1, 100):
    command.append("tmux send-keys -t phantom:phantom 'thread " + str(i) + "' C-m")
    command.append("tmux send-keys -t phantom:phantom 'bt' C-m")

command = ['tmux send-keys -t phantom:phantom C-c',
		   'tmux clear-history -t phantom:phantom',
		   'tmux send-keys -t phantom:phantom \'info threads\' C-m'
		  ]
output = run_command_on_instances(command, instances)
		   # 'tmux copy-mode -t phantom:phantom\; send-keys -t phantom:phantom \'M->\' C-e C-space \'M-<\' C-a M-w',
           # 'tmux save-buffer -t phantom /tmp/foo',
           # 'tail -n ' + tail_size + ' /tmp/foo']
pprint(output)
command.append("tmux send-keys -t phantom:phantom 'c' C-m")
output = run_command_on_instances(command, instances)
print(command)
print("done")
