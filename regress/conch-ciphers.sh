#	$OpenBSD: conch-ciphers.sh,v 1.1 2008/06/28 13:57:25 djm Exp $
#	Placed in the Public Domain.

tid="conch ciphers"

DATA=/bin/ls
COPY=${OBJ}/copy

set -e

if test "x$REGRESS_INTEROP_CONCH" != "xyes" ; then
	fatal "conch interop tests not enabled"
fi

start_sshd

for c in aes256-ctr aes256-cbc aes192-ctr aes192-cbc aes128-ctr aes128-cbc \
         cast128-cbc blowfish 3des-cbc ; do
	verbose "$tid: cipher $c"
	rm -f ${COPY}
	${CONCH} --identity $OBJ/rsa --port $PORT --user $USER \
	         --known-hosts $OBJ/known_hosts \
	         127.0.0.1 cat ${DATA} > ${COPY} 2>/dev/null
	if [ $? -ne 0 ]; then
		fail "ssh cat $DATA failed"
	fi
	cmp ${DATA} ${COPY}		|| fail "corrupted copy"
done
rm -f ${COPY}

