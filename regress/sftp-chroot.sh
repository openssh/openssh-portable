#	$OpenBSD: sftp-chroot.sh,v 1.1 2013/04/18 02:46:12 djm Exp $
#	Placed in the Public Domain.

tid="sftp in chroot"

COPY=${OBJ}/copy
CHROOT=/var/run
FILENAME=testdata_${USER}
PRIVDATA=${CHROOT}/${FILENAME}

if [ -z "$SUDO" ]; then
	fatal "need SUDO to create file in /var/run, test won't work without"
fi

$SUDO sh -c "echo mekmitastdigoat > $PRIVDATA" || \
	fatal "create $PRIVDATA failed"

start_sshd -oChrootDirectory=$CHROOT -oForceCommand="internal-sftp -d /"

verbose "test $tid: get"
rm -f ${COPY}
${SFTP} -qS "$SSH" -F $OBJ/ssh_config host:/${FILENAME} $COPY || \
	fatal "Fetch ${FILENAME} failed"
cmp $PRIVDATA $COPY || fail "$PRIVDATA $COPY differ"

$SUDO rm $PRIVDATA
