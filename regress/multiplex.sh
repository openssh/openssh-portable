#	$OpenBSD: multiplex.sh,v 1.2 2004/06/16 13:16:40 dtucker Exp $
#	Placed in the Public Domain.

CTL=$OBJ/ctl-sock

tid="connection multiplexing"

start_sshd

trace "start master, fork to background"
${SSH} -2 -MS$CTL -F $OBJ/ssh_config -f somehost sleep 60

trace "ssh transfer over multiplexed connection and check result"
${SSH} -S$CTL otherhost cat /bin/ls > $OBJ/ls.copy
test -f $OBJ/ls.copy			|| fail "failed copy /bin/ls"
cmp /bin/ls $OBJ/ls.copy		|| fail "corrupted copy of /bin/ls"

trace "ssh transfer over multiplexed connection and check result"
${SSH} -S $CTL otherhost cat /bin/ls > $OBJ/ls.copy
test -f $OBJ/ls.copy			|| fail "failed copy /bin/ls"
cmp /bin/ls $OBJ/ls.copy		|| fail "corrupted copy of /bin/ls"

rm -f $OBJ/ls.copy
trace "sftp transfer over multiplexed connection and check result"
echo "get /bin/ls $OBJ/ls.copy" | \
	${SFTP} -oControlPath=$CTL otherhost >/dev/null 2>&1
test -f $OBJ/ls.copy			|| fail "failed copy /bin/ls"
cmp /bin/ls $OBJ/ls.copy		|| fail "corrupted copy of /bin/ls"

rm -f $OBJ/ls.copy
trace "scp transfer over multiplexed connection and check result"
${SCP} -oControlPath=$CTL otherhost:/bin/ls $OBJ/ls.copy >/dev/null 2>&1
test -f $OBJ/ls.copy			|| fail "failed copy /bin/ls"
cmp /bin/ls $OBJ/ls.copy		|| fail "corrupted copy of /bin/ls"

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

sleep 30 # early close test sleeps 5 seconds per test
