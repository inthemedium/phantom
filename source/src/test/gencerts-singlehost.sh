HOSTS="test01 test02 test03 test04 test05 test06 test07 test08 test09 test10 test11 test12 test13 test14 test15 test16 test17 test18 test19 test20"
PORT="8080"

CERTPOSTS="cc pbc rc"
for i in $HOSTS;
	do
	for j in $CERTPOSTS;
		do
		openssl genrsa 1024 > "$i-privkey-$j.pem";
		yes XX | openssl req -new -x509 -nodes -sha1 -days 365 -key "$i-privkey-$j.pem" > "$i-$j.pem";
	done
IP="127.0.0.1"
let "PORT=PORT+1"
cat << EOF > $i.conf
<?xml version="1.0" encoding="iso-8859-1" ?>

<phantomconfig>
<ip>$IP</ip>
<port>$PORT</port>
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
