# this is an example script that can be run with execfile('ipython_test.py') from inside the ipython embedded shell
import re

phantom_addrs = run_command_on_instances(['ifconfig phantom | grep inet | cut -d: -f2- | cut -d\/ -f1'], instances)

ping_mat = {}
problem_instances = set(instances)
for result in phantom_addrs:
    try:
        dest_ipv6_addr = result.output[0].strip()
    except IndexError:
        continue
    foo = run_command_on_instances(['ifconfig phantom | grep inet | cut -d: -f2- | cut -d\/ -f1 && ping6 -c 2 ' + dest_ipv6_addr], instances)
    ping_mat[dest_ipv6_addr] = {}
    print
    print "couldn't ping", dest_ipv6_addr, "from..."
    for nes_result in foo:
        src_ipv6_addr = nes_result.output[0].strip()
        ping_mat[dest_ipv6_addr][src_ipv6_addr] = nes_result.exit_status
        if nes_result.exit_status != 0:
            print src_ipv6_addr, nes_result.exit_status
        else:
            try:
                (problem_instances.remove(nes_result.instance) if nes_result.output[0].strip() != dest_ipv6_addr else False)
            except KeyError:
                pass

command = ['tmux copy-mode -t phantom:phantom\; send-keys \'M->\' C-e C-space \'M-<\' C-a C-w',
           'tmux save-buffer -t phantom /tmp/foo',
           'tail -n +0 /tmp/foo']
tmux_dump = run_command_on_instances(command, instances)

node_types = {}

for inst in tmux_dump:
    try:
        out_str = "".join(inst.output)
        ipv6_addr = re.search(r"path built successfully, have ap (.*)", out_str).group(1)
        cons_path = re.search(r"starting to construct (entry|exit)-path", out_str).group(1)
        node_types[ipv6_addr] = cons_path
    except AttributeError:
        pass

def pprint_mat(mat, node_types):
    for i in sorted(mat.keys()):
        print i + '\t\t',
        try:
            print node_types[i] + '\t\t',
        except KeyError:
            print '????' + '\t\t',
        for j in sorted(mat[i].keys()):
            print mat[i][j],
        print
pprint_mat(ping_mat, node_types)
pprint(problem_instances)
