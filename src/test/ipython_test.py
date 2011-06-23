# this is an example script that can be run with execfile('ipython_test.py') from inside the ipython embedded shell
phantom_addrs = run_command_on_instances(['ifconfig phantom | grep inet | cut -d: -f2- | cut -d\/ -f1'], instances)

ping_mat = {}
problem_instances = set(instances)
for result in phantom_addrs:
    dest_ipv6_addr = result.output[0].strip()
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

def pprint_mat(mat):
    for i in sorted(mat.keys()):
        print i + '\t\t',
        for j in sorted(mat[i].keys()):
            print mat[i][j],
        print
pprint_mat(ping_mat)
pprint(problem_instances)
