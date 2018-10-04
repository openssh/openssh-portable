#	$OpenBSD: keyscan.sh,v 1.6 2017/04/30 23:34:55 djm Exp $
#	Placed in the Public Domain.

tid="keyscan"

# remove DSA hostkey
rm -f ${OBJ}/host.dsa

start_sshd

if [ "$os" == "windows" ]; then
	# Remove CR (carriage return)
	KEYTYPES=`${SSH} -Q key-plain | sed 's/\r$//'`
else
	KEYTYPES=`${SSH} -Q key-plain`
fi
for t in $KEYTYPES; do
	trace "keyscan type $t"
	${SSHKEYSCAN} -t $t -p $PORT 127.0.0.1 127.0.0.1 127.0.0.1 \
		> /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-keyscan -t $t failed with: $r"
	fi
done
