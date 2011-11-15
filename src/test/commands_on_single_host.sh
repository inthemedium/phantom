HOSTS="test01 test02 test03 test04 test05 test06 test07 test08 test09 test10 test11 test12 test13 test14 test15 test16 test17 test18 test19 test20"

ssh $1 "sudo killall -9 gdb phantom tmux"

ssh $1 "tmux new-session -d -s phantom -n phantom"
for i in $HOSTS;
do
	ssh $1 "tmux new-window -t phantom: -n $i && tmux send-keys -t phantom:$i 'cd ~/phantom/src/ && sudo gdb --args ./phantom -h $i' C-m && tmux send-keys -t phantom:$i 'set print thread-events off' C-m && tmux send-keys -t phantom:$i 'break tunnel_worker' C-m && tmux send-keys -t phantom:$i 'condition 1 tw->conn->peer_port==8081' C-m && tmux send-keys -t phantom:$i 'run' C-m"
done
