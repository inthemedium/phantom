#!/bin/bash
# TODO re-implement with cached entries -> generate contact block for each host first, then generate file and write out in one big write

# generate host list
HOSTS="`ls *.conf`"
HOSTS="${HOSTS//.conf/}"		# trim file list items of ".conf" suffix

for i in $HOSTS;
	do
	# display status / progress
	echo $i

	# check if list file exists
	if [ -e "$i-kadnodes.list" ]
	then
		rm "$i-kadnodes.list"
	fi

	for j in $HOSTS;
		do
		if [ "$i" != "$j" ]			# do not add itself as contact
		then
			# all four separated by newline:
			# 1. SHA-1 hash of the contact's communication certificate (this is also the node's kademlia ID)
			# 2. Port of the contact, IP of the contact, length of item 3, length of item 4
			# 3. The communication certificate of the contact = the -cc.pem file for this contact
			# 4. The path building certificate of the contact = the -pbc.pem file for this contact

			# item 1
			sha1sum "$j-cc.pem"|cut -b 1-40|echo -n -e $(tr -d '[:space:]' | sed 's/../\\x&/g') >> "$i-kadnodes.list"
			echo "" >> "$i-kadnodes.list"	# didnt get the escaping or quoting right with the sed call inside echo ``, so it is extra here
			# hex2bin from here, also perl version there http://www.linuxquestions.org/questions/programming-9/how-can-i-convert-hex-to-binary-in-a-perl-script-653135/page2.html
			# TODO perl rewrite, hmmm? ;-)

			# item 2
			port=`grep "<port>" "$j.conf"`
			port="${port#<port>}"
			port="${port%</port>}"
			ip=`grep "<ip>" "$j.conf"`
			ip="${ip#<ip>}"
			ip="${ip%</ip>}"
			echo $port $ip `stat -c%s "$j-cc.pem"` `stat -c%s "$j-pbc.pem"` >> "$i-kadnodes.list"

			# item 3
			cat "$j-cc.pem" >> "$i-kadnodes.list"

			# item 4
			cat "$j-pbc.pem" >> "$i-kadnodes.list"
		fi
	done
done
