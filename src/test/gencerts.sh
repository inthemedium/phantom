#!/bin/bash

if [ -n "${1}" ]
then
   HOSTS="$1"
else
   echo "Enter the hosts for which you wish to generate a config file for sperated by a space:"
   read HOSTS
fi

echo $HOSTS

CERTPOSTS="cc pbc rc"
for i in $HOSTS;
	do
	for j in $CERTPOSTS;
		do
		openssl genrsa 2048 > "$i-privkey-$j.pem";
		yes XX | openssl req -new -x509 -nodes -sha1 -days 365 -key "$i-privkey-$j.pem" > "$i-$j.pem";
	done

	# seccloud specific!
	if ! host -t A "$i"
	then
		IP=`echo "$i" | cut -b 4- | sed -e 's/-/./g'`
	else
		IP=`host -t A $i | cut -d ' ' -f 4`
	fi
cat << EOF > $i.conf
<?xml version="1.0" encoding="iso-8859-1" ?>

<phantomconfig>
<ip>$IP</ip>
<port>8080</port>
<rsa_len>2048</rsa_len>
<xnodes>3</xnodes>
<ynodes>7</ynodes>
<keys>15</keys>
<kadnodefile>test/$i-kadnodes.list</kadnodefile>
<kaddata>/tmp</kaddata>
<communicationcertificate>test/$i-cc.pem</communicationcertificate>
<constructioncertificate>test/$i-pbc.pem</constructioncertificate>
<routingcertificate>test/$i-rc.pem</routingcertificate>
<communicationcertificateprivate>test/$i-privkey-cc.pem</communicationcertificateprivate>
<constructioncertificateprivate>test/$i-privkey-pbc.pem</constructioncertificateprivate>
<routingcertificateprivate>test/$i-privkey-rc.pem</routingcertificateprivate>
</phantomconfig>
EOF
touch "$i-kadnodes.list"
touch "$i-kad.data"
done
