#	$OpenBSD: keyscan.sh,v 1.12 2019/12/16 02:39:05 djm Exp $
#	Placed in the Public Domain.

tid="keyscan"

for i in $SSH_KEYTYPES; do
	if [ -z "$algs" ]; then
		algs="$i"
	else
		algs="$algs,$i"
	fi
done
echo "HostKeyAlgorithms $algs" >> $OBJ/sshd_config

start_sshd

for t in $SSH_KEYTYPES; do
	trace "keyscan type $t"
	${SSHKEYSCAN} -t $t -p $PORT 127.0.0.1 127.0.0.1 127.0.0.1 \
		> /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-keyscan -t $t failed with: $r"
	fi
done
