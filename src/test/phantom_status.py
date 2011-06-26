# this script get's the output of each instance of phantom
# set tail_size in ipython to limit output
try:
    tail_size
except (NameError):
    tail_size = '+0'

command = ['tmux copy-mode -t phantom\; send-keys \'M->\' C-e C-space \'M-<\' C-a C-w',
           'tmux save-buffer /tmp/foo',
           'tail -n ' + tail_size + ' /tmp/foo']
output = run_command_on_instances(command, instances)
pprint(output)
# straight bash version:
# tmux copy-mode -t phantom\; send-keys 'M->' C-e C-space 'M-<' C-a C-w && tmux save-buffer /tmp/foo && cat /tmp/foo
