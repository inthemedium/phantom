#!/bin/bash
#XXX change this to your needs
USER=phantom_user
TUNCTL=/path/to/tunnel_binary

start() {
	echo start
	$TUNCTL -u $USER -t phantom
	ip link set phantom up
}

stop() {
	echo stop
	$TUNCTL -d phantom
}


case "$1" in
start)
	start
;;
stop)
	stop
;;
restart)
	stop
	start
;;
help|*)
	echo "Usage is $0 [start | stop | help | restart]"
;;
esac
