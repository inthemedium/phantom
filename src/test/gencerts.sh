HOSTS="faui00a faui00b faui00c faui00d faui00e faui00f faui00g faui00h faui00i faui00j faui00k faui03a faui00l faui00m faui00n faui00o faui00p faui00q faui00r faui00s faui00t"

CERTPOSTS="cc pbc rc"
for i in $HOSTS;
	do
	for j in $CERTPOSTS;
		do
		openssl genrsa 1024 > "$i-privkey-$j.pem";
		yes XX | openssl req -new -x509 -nodes -sha1 -days 365 -key "$i-privkey-$j.pem" > "$i-$j.pem";
	done
IP=`host -t A $i | cut -d ' ' -f 4`
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
