HOSTS="test01 test02 test03 test04 test05 test06 test07 test08 test09 test10 test11 test12 test13 test14 test15 test16 test17 test18 test19 test20"

ssh $1 "sudo killall -9 gdb phantom tmux"

branch_name="$(git symbolic-ref HEAD 2>/dev/null)" ||
branch_name="(unnamed branch)"     # detached HEAD
branch_name=${branch_name##refs/heads/}

git diff | ssh $1 "cd phantom && git checkout -f && git pull && git checkout $branch_name && git apply && cd protos && ./generate_protos.sh && cd ../src && make"

ssh $1 "tmux new-session -d -s phantom -n phantom && cd phantom/src/test && rm -rf *.conf *.pem *.data *.list && ./gencerts-singlehost.sh \"$HOSTS\" && ./genkadnodes-list.sh"
for i in $HOSTS;
do
	ssh $1 "tmux new-window -t phantom: -n $i && tmux send-keys -t phantom:$i 'cd ~/phantom/src/ && sudo gdb --args ./phantom -h $i' C-m && tmux send-keys -t phantom:$i 'set print thread-events off' C-m && tmux send-keys -t phantom:$i 'break become_x_node' C-m && tmux send-keys -t phantom:$i 'run' C-m"
done
