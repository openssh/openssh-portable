#	$OpenBSD: multiplex.sh,v 1.5 2004/06/17 06:19:06 dtucker Exp $
#	Placed in the Public Domain.

CTL=$OBJ/ctl-sock

tid="connection multiplexing"

DATA=/bin/ls${EXEEXT}
COPY=$OBJ/ls.copy

start_sshd

trace "start master, fork to background"
${SSH} -2 -MS$CTL -F $OBJ/ssh_config -f somehost sleep 120

rm -f ${COPY}
trace "ssh transfer over multiplexed connection and check result"
${SSH} -S$CTL otherhost cat ${DATA} > ${COPY}
test -f ${COPY}			|| fail "ssh -Sctl: failed copy ${DATA}" 
cmp ${DATA} ${COPY}		|| fail "ssh -Sctl: corrupted copy of ${DATA}"

rm -f ${COPY}
trace "ssh transfer over multiplexed connection and check result"
${SSH} -S $CTL otherhost cat ${DATA} > ${COPY}
test -f ${COPY}			|| fail "ssh -S ctl: failed copy ${DATA}" 
cmp ${DATA} ${COPY}		|| fail "ssh -S ctl: corrupted copy of ${DATA}"

rm -f ${COPY}
trace "sftp transfer over multiplexed connection and check result"
echo "get ${DATA} ${COPY}" | \
	${SFTP} -oControlPath=$CTL otherhost >/dev/null 2>&1
test -f ${COPY}			|| fail "sftp: failed copy ${DATA}" 
cmp ${DATA} ${COPY}		|| fail "sftp: corrupted copy of ${DATA}"

rm -f ${COPY}
trace "scp transfer over multiplexed connection and check result"
${SCP} -oControlPath=$CTL otherhost:${DATA} ${COPY} >/dev/null 2>&1
test -f ${COPY}			|| fail "scp: failed copy ${DATA}" 
cmp ${DATA} ${COPY}		|| fail "scp: corrupted copy of ${DATA}"

rm -f ${COPY}

for s in 0 1 4 5 44; do
	trace "exit status $s over multiplexed connection"
	verbose "test $tid: status $s"
	${SSH} -S $CTL otherhost exit $s
	r=$?
	if [ $r -ne $s ]; then
		fail "exit code mismatch for protocol $p: $r != $s"
	fi

	# same with early close of stdout/err
	trace "exit status $s with early close over multiplexed connection"
	${SSH} -S $CTL -n otherhost \
                exec sh -c \'"sleep 2; exec > /dev/null 2>&1; sleep 3; exit $s"\'
	r=$?
	if [ $r -ne $s ]; then
		fail "exit code (with sleep) mismatch for protocol $p: $r != $s"
	fi
done

# kill master, remove control socket.  ssh -MS will exit when sleep exits
$SUDO kill `cat $PIDFILE`
rm -f $CTL
