# this is an example script that can be run with execfile('ipython_test.py') from inside the ipython embedded shell
import re

command = ['tmux copy-mode -t phantom:phantom\; send-keys \'M->\' C-e C-space \'M-<\' C-a C-w',
           'tmux save-buffer -t phantom /tmp/foo',
           'tail -n +0 /tmp/foo']
output = run_command_on_instances(command, instances)

node_types = {}

for inst in output:
    try:
        out_str = "".join(inst.output)
        inst.ipv6_addr = re.search(r"path built successfully, have ap (.*)", out_str).group(1)
        inst.path_type = re.search(r"starting to construct (entry|exit)-path", out_str).group(1)
        inst.output = None
    except AttributeError:
        inst.output = None
        inst.ipv6_addr = None
        inst.path_type = None
        pass
    finally:
        print "%s %s %s %s" % (inst.hostname, inst.hostname_prv, inst.ipv6_addr, inst.path_type)
