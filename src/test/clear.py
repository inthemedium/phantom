# this script restart all the phantom processes running in tmux
command = ['! [ -a ~/PERSISTENT_GDB ]',
           'tmux clear-history -t phantom:phantom'
          ]
output = run_command_on_instances(command, instances)
pprint(output)
