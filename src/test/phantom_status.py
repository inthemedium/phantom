# this is an example script that can be run with execfile('ipython_test.py') from inside the ipython embedded shell
command = ['tmux copy-mode -t phantom\; send-keys \'M->\' C-e C-space \'M-<\' C-a C-w',
           'tmux save-buffer /tmp/foo',
           'cat /tmp/foo']
pprint(run_command_on_instances(command, instances))
# straight bash version:
# tmux copy-mode -t phantom\; send-keys 'M->' C-e C-space 'M-<' C-a C-w && tmux save-buffer /tmp/foo && cat /tmp/foo
