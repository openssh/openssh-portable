#	$OpenBSD: multiplex.sh,v 1.43 2026/09/23 21:45:51 djm Exp $
#	Placed in the Public Domain.

tid="connection multiplexing"

trace "will use ProxyCommand $proxycmd"
make_tmpdir
CTL=${SSH_REGRESS_TMP}/ctl-sock

if config_defined DISABLE_FD_PASSING ; then
	skip "not supported on this platform (FD passing disabled)"
fi

P=3301  # test port

wait_for_mux_master_ready()
{
	for i in 1 2 3 4 5 6 7 8 9; do
		${SSH} -F $OBJ/ssh_config -S $CTL -Ocheck otherhost \
		    >/dev/null 2>&1 && return 0
		sleep $i
	done
	fatal "mux master never becomes ready"
}

maybe_add_scp_path_to_sshd
enable_all_kexes_in_sshd
start_sshd

start_mux_master()
{
	trace "start master, fork to background"
	${SSH} -Nn2 -MS$CTL -F $OBJ/ssh_config -oSendEnv="_XXX_TEST" somehost \
	    -E $TEST_REGRESS_LOGFILE 2>&1 &
	# NB. $SSH_PID will be killed by test-exec.sh:cleanup on fatal errors.
	SSH_PID=$!
	wait_for_mux_master_ready
}

start_mux_master

verbose "test $tid: setenv"
trace "setenv over multiplexed connection"
_XXX_TEST=blah ${SSH} -F $OBJ/ssh_config -oSendEnv="_XXX_TEST" -S$CTL otherhost sh << 'EOF'
	test X"$_XXX_TEST" = X"blah"
EOF
if [ $? -ne 0 ]; then
	fail "environment not found"
fi

verbose "test $tid: envpass"
trace "env passing over multiplexed connection"
${SSH} -F $OBJ/ssh_config -oSetEnv="_XXX_TEST=foo" -S$CTL otherhost sh << 'EOF'
	test X"$_XXX_TEST" = X"foo"
EOF
if [ $? -ne 0 ]; then
	fail "environment not found"
fi

for mode in "" "-Oproxy"; do
	verbose "test $tid: transfer $mode"
	rm -f ${COPY}
	trace "ssh transfer over $mode multiplexed connection and check result"
	${SSH} $mode -F $OBJ/ssh_config -S$CTL otherhost cat ${DATA} > ${COPY}
	test -f ${COPY}		|| fail "ssh -Sctl: failed copy ${DATA}" 
	cmp ${DATA} ${COPY}	|| fail "ssh -Sctl: corrupted copy of ${DATA}"

	rm -f ${COPY}
	trace "ssh transfer over $mode multiplexed connection and check result"
	${SSH} $mode -F $OBJ/ssh_config -S $CTL otherhost cat ${DATA} > ${COPY}
	test -f ${COPY}		|| fail "ssh -S ctl: failed copy ${DATA}" 
	cmp ${DATA} ${COPY}	|| fail "ssh -S ctl: corrupted copy of ${DATA}"
done

rm -f ${COPY}
trace "sftp transfer over multiplexed connection and check result"
echo "get ${DATA} ${COPY}" | \
	${SFTP} -S ${SSH} -F $OBJ/ssh_config -oControlPath=$CTL otherhost >>$TEST_REGRESS_LOGFILE 2>&1
test -f ${COPY}			|| fail "sftp: failed copy ${DATA}" 
cmp ${DATA} ${COPY}		|| fail "sftp: corrupted copy of ${DATA}"

rm -f ${COPY}
trace "scp transfer over multiplexed connection and check result"
${SCP} -S ${SSH} -F $OBJ/ssh_config -oControlPath=$CTL otherhost:${DATA} ${COPY} >>$TEST_REGRESS_LOGFILE 2>&1
test -f ${COPY}			|| fail "scp: failed copy ${DATA}" 
cmp ${DATA} ${COPY}		|| fail "scp: corrupted copy of ${DATA}"

rm -f ${COPY}
verbose "test $tid: forward"
trace "forward over TCP/IP and check result"
$NC -N -l 127.0.0.1 $((${PORT} + 1)) < ${DATA} >`ssh_logfile nc` &
netcat_pid=$!
${SSH} -F $OBJ/ssh_config -S $CTL -Oforward -L127.0.0.1:$((${PORT} + 2)):127.0.0.1:$((${PORT} + 1)) otherhost >>$TEST_SSH_LOGFILE 2>&1
sleep 1  # XXX remove once race fixed
$NC 127.0.0.1 $((${PORT} + 2)) < /dev/null > ${COPY}
cmp ${DATA} ${COPY}		|| fail "ssh: corrupted copy of ${DATA}"
kill $netcat_pid 2>/dev/null
rm -f ${COPY} $OBJ/unix-[123].fwd

trace "forward over UNIX and check result"
$NC -N -Ul $OBJ/unix-1.fwd < ${DATA} > /dev/null &
netcat_pid=$!
${SSH} -F $OBJ/ssh_config -S $CTL -Oforward -L$OBJ/unix-2.fwd:$OBJ/unix-1.fwd otherhost >>$TEST_SSH_LOGFILE 2>&1
${SSH} -F $OBJ/ssh_config -S $CTL -Oforward -R$OBJ/unix-3.fwd:$OBJ/unix-2.fwd otherhost >>$TEST_SSH_LOGFILE 2>&1
sleep 1  # XXX remove once race fixed
$NC -U $OBJ/unix-3.fwd < /dev/null > ${COPY}
cmp ${DATA} ${COPY}		|| fail "ssh: corrupted copy of ${DATA}"
kill $netcat_pid 2>/dev/null
rm -f ${COPY} $OBJ/unix-[123].fwd

for s in 0 1 4 5 44; do
   for mode in "" "-Oproxy"; do
	trace "exit status $s over multiplexed connection ($mode)"
	verbose "test $tid: status $s ($mode)"
	${SSH} -F $OBJ/ssh_config -S $CTL $mode otherhost exit $s
	r=$?
	if [ $r -ne $s ]; then
		fail "exit code mismatch: $r != $s"
	fi

	# same with early close of stdout/err
	trace "exit status $s with early close over multiplexed connection ($mode)"
	${SSH} -F $OBJ/ssh_config -S $CTL -n $mode otherhost \
                exec sh -c \'"sleep 2; exec > /dev/null 2>&1; sleep 3; exit $s"\'
	r=$?
	if [ $r -ne $s ]; then
		fail "exit code (with sleep) mismatch: $r != $s"
	fi
   done
done

verbose "test $tid: cmd check"
${SSH} -F $OBJ/ssh_config -S $CTL -Ocheck otherhost >>$TEST_REGRESS_LOGFILE 2>&1 \
    || fail "check command failed" 

verbose "test $tid: cmd forward local (TCP)"
${SSH} -F $OBJ/ssh_config -S $CTL -Oforward -L $P:localhost:$PORT otherhost \
     || fail "request local forward failed"
sleep 1  # XXX remove once race fixed
${SSH} -F $OBJ/ssh_config -p$P otherhost true \
     || fail "connect to local forward port failed"
${SSH} -F $OBJ/ssh_config -S $CTL -Ocancel -L $P:localhost:$PORT otherhost \
     || fail "cancel local forward failed"
${SSH} -F $OBJ/ssh_config -p$P otherhost true \
     && fail "local forward port still listening"

verbose "test $tid: cmd forward remote (TCP)"
${SSH} -F $OBJ/ssh_config -S $CTL -Oforward -R $P:localhost:$PORT otherhost \
     || fail "request remote forward failed"
sleep 1  # XXX remove once race fixed
${SSH} -F $OBJ/ssh_config -p$P otherhost true \
     || fail "connect to remote forwarded port failed"
${SSH} -F $OBJ/ssh_config -S $CTL -Ocancel -R $P:localhost:$PORT otherhost \
     || fail "cancel remote forward failed"
${SSH} -F $OBJ/ssh_config -p$P otherhost true \
     && fail "remote forward port still listening"

verbose "test $tid: cmd forward local (UNIX)"
${SSH} -F $OBJ/ssh_config -S $CTL -Oforward -L $OBJ/unix-1.fwd:localhost:$PORT otherhost \
     || fail "request local forward failed"
sleep 1  # XXX remove once race fixed
echo "" | $NC -U $OBJ/unix-1.fwd | \
    grep "Invalid SSH identification string" >/dev/null 2>&1 \
     || fail "connect to local forward path failed"
${SSH} -F $OBJ/ssh_config -S $CTL -Ocancel -L $OBJ/unix-1.fwd:localhost:$PORT otherhost \
     || fail "cancel local forward failed"
N=$(echo "xyzzy" | $NC -U $OBJ/unix-1.fwd 2>&1 | grep "xyzzy" | wc -l)
test ${N} -eq 0 || fail "local forward path still listening"
rm -f $OBJ/unix-1.fwd

verbose "test $tid: cmd forward remote (UNIX)"
${SSH} -F $OBJ/ssh_config -S $CTL -Oforward -R $OBJ/unix-1.fwd:localhost:$PORT otherhost \
     || fail "request remote forward failed"
sleep 1  # XXX remove once race fixed
echo "" | $NC -U $OBJ/unix-1.fwd | \
    grep "Invalid SSH identification string" >/dev/null 2>&1 \
     || fail "connect to remote forwarded path failed"
${SSH} -F $OBJ/ssh_config -S $CTL -Ocancel -R $OBJ/unix-1.fwd:localhost:$PORT otherhost \
     || fail "cancel remote forward failed"
N=$(echo "xyzzy" | $NC -U $OBJ/unix-1.fwd 2>&1 | grep "xyzzy" | wc -l)
test ${N} -eq 0 || fail "remote forward path still listening"
rm -f $OBJ/unix-1.fwd

verbose "test $tid: cmd conninfo"
conninfo=`${SSH} -F $OBJ/ssh_config -S $CTL -Oconninfo otherhost` \
     || fail "request remote forward failed"
if ! echo "$conninfo" | egrep -- "-> 127.0.0.1:$port" >/dev/null; then
       fail "conninfo"
fi

get_mux_sshd_pid() {
	MUX_SSHD_NET_PID=`echo 'echo $PPID' | \
	    ${SSH} -F $OBJ/ssh_config -S $CTL otherhost exec sh 2>/dev/null`
}

mux_log_count() {
	_c=`grep -c "$1" "$TEST_REGRESS_LOGFILE" 2>/dev/null || true`
	echo "${_c:-0}"
}

wait_mux_log_inc() {
	_pat="$1"
	_base="$2"
	_j=0
	while [ "$_j" -lt 30 ]; do
		kill -0 "$SSH_PID" 2>/dev/null || return 1
		_cur=`mux_log_count "$_pat"`
		[ "$_cur" -gt "$_base" ] && return 0
		sleep 1
		_j=`expr $_j + 1`
	done
	return 1
}

recover_mux_master_if_dead() {
	if ! kill -0 "$SSH_PID" 2>/dev/null; then
		wait "$SSH_PID" 2>/dev/null
		rm -f "$CTL"
		start_mux_master
		get_mux_sshd_pid
	fi
}

get_mux_sshd_pid

if [ -z "$MUX_SSHD_NET_PID" ] || ! $SUDO kill -0 "$MUX_SSHD_NET_PID" 2>/dev/null; then
	fail "missing mux sshd user child pid"
else
	verbose "test $tid: stdio forward client abort during open"
	base_new=`mux_log_count "mux_master_process_stdio_fwd: channel_new:"`
	base_clean=`mux_log_count "mux_master_control_cleanup_cb: entering"`
	base_confirm=`mux_log_count "mux_stdio_confirm:.*control channel already closed"`
	trap '$SUDO kill -CONT "$MUX_SSHD_NET_PID" 2>/dev/null; cleanup' INT TERM EXIT
	$SUDO kill -STOP "$MUX_SSHD_NET_PID"
	${SSH} -F $OBJ/ssh_config -S $CTL -W 127.0.0.1:$PORT otherhost </dev/null >/dev/null 2>&1 &
	mux_pid=$!
	trap '$SUDO kill -CONT "$MUX_SSHD_NET_PID" 2>/dev/null; kill "$mux_pid" 2>/dev/null; cleanup' INT TERM EXIT
	wait_mux_log_inc "mux_master_process_stdio_fwd: channel_new:" "$base_new" || fail "stdio fwd open not seen by master"
	kill "$mux_pid" 2>/dev/null
	wait "$mux_pid" 2>/dev/null
	wait_mux_log_inc "mux_master_control_cleanup_cb: entering" "$base_clean" || fail "stdio fwd client disconnect not detected while paused"
	$SUDO kill -CONT "$MUX_SSHD_NET_PID" 2>/dev/null
	trap cleanup INT TERM EXIT
	wait_mux_log_inc "mux_stdio_confirm:.*control channel already closed" "$base_confirm" || fail "stdio fwd confirm not seen by master"
	${SSH} -F $OBJ/ssh_config -S $CTL -Ocheck otherhost >/dev/null 2>&1 || fail "master died after stdio fwd abort"
	${SSH} -F $OBJ/ssh_config -S $CTL otherhost true || fail "session after stdio fwd abort failed"
	recover_mux_master_if_dead

	verbose "test $tid: session client abort during open"
	rm -f $OBJ/orphaned_cmd
	base_new=`mux_log_count "mux_master_process_new_session: channel_new:"`
	base_clean=`mux_log_count "mux_master_control_cleanup_cb: entering"`
	base_confirm=`mux_log_count "mux_session_confirm:.*control channel already closed"`
	trap '$SUDO kill -CONT "$MUX_SSHD_NET_PID" 2>/dev/null; cleanup' INT TERM EXIT
	$SUDO kill -STOP "$MUX_SSHD_NET_PID"
	${SSH} -F $OBJ/ssh_config -S $CTL otherhost "touch $OBJ/orphaned_cmd" </dev/null >/dev/null 2>&1 &
	mux_pid=$!
	trap '$SUDO kill -CONT "$MUX_SSHD_NET_PID" 2>/dev/null; kill "$mux_pid" 2>/dev/null; cleanup' INT TERM EXIT
	wait_mux_log_inc "mux_master_process_new_session: channel_new:" "$base_new" || fail "session open not seen by master"
	kill "$mux_pid" 2>/dev/null
	wait "$mux_pid" 2>/dev/null
	wait_mux_log_inc "mux_master_control_cleanup_cb: entering" "$base_clean" || fail "session client disconnect not detected while paused"
	$SUDO kill -CONT "$MUX_SSHD_NET_PID" 2>/dev/null
	trap cleanup INT TERM EXIT
	wait_mux_log_inc "mux_session_confirm:.*control channel already closed" "$base_confirm" || fail "session confirm not seen by master"
	${SSH} -F $OBJ/ssh_config -S $CTL -Ocheck otherhost >/dev/null 2>&1 || fail "master died after session abort"
	${SSH} -F $OBJ/ssh_config -S $CTL otherhost true || fail "session after session abort failed"
	test ! -f $OBJ/orphaned_cmd || fail "orphaned session command executed"
	rm -f $OBJ/orphaned_cmd
	recover_mux_master_if_dead

	verbose "test $tid: remote forward client abort during open"
	base_new=`mux_log_count "mux_master_process_open_fwd: channel"`
	base_clean=`mux_log_count "mux_master_control_cleanup_cb: entering"`
	base_proxy=`mux_log_count "mux_master_process_proxy: channel"`
	base_confirm=`mux_log_count "mux_confirm_remote_forward: control channel already closed"`
	trap '$SUDO kill -CONT "$MUX_SSHD_NET_PID" 2>/dev/null; cleanup' INT TERM EXIT
	$SUDO kill -STOP "$MUX_SSHD_NET_PID"
	${SSH} -F $OBJ/ssh_config -S $CTL -Oforward -R 127.0.0.1:0:127.0.0.1:$PORT otherhost </dev/null >/dev/null 2>&1 &
	mux_pid=$!
	trap '$SUDO kill -CONT "$MUX_SSHD_NET_PID" 2>/dev/null; kill "$mux_pid" 2>/dev/null; cleanup' INT TERM EXIT
	wait_mux_log_inc "mux_master_process_open_fwd: channel" "$base_new" || fail "remote fwd open not seen by master"
	kill "$mux_pid" 2>/dev/null
	wait "$mux_pid" 2>/dev/null
	wait_mux_log_inc "mux_master_control_cleanup_cb: entering" "$base_clean" || fail "remote fwd client disconnect not detected while paused"
	${SSH} -F $OBJ/ssh_config -S $CTL -N -Oproxy otherhost </dev/null >/dev/null 2>&1 &
	proxy_pid=$!
	trap '$SUDO kill -CONT "$MUX_SSHD_NET_PID" 2>/dev/null; kill "$proxy_pid" 2>/dev/null; cleanup' INT TERM EXIT
	wait_mux_log_inc "mux_master_process_proxy: channel" "$base_proxy" || fail "proxy not seen by master"
	$SUDO kill -CONT "$MUX_SSHD_NET_PID" 2>/dev/null
	trap 'kill "$proxy_pid" 2>/dev/null; cleanup' INT TERM EXIT
	wait_mux_log_inc "mux_confirm_remote_forward: control channel already closed" "$base_confirm" || fail "remote fwd confirm not seen by master"
	${SSH} -F $OBJ/ssh_config -S $CTL -Ocheck otherhost >/dev/null 2>&1 || fail "master died after remote fwd abort"
	${SSH} -F $OBJ/ssh_config -S $CTL otherhost true || fail "session after remote fwd abort failed"
	kill "$proxy_pid" 2>/dev/null
	wait "$proxy_pid" 2>/dev/null
	trap cleanup INT TERM EXIT
	recover_mux_master_if_dead
fi

verbose "test $tid: cmd exit"
${SSH} -F $OBJ/ssh_config -S $CTL -Oexit otherhost >>$TEST_REGRESS_LOGFILE 2>&1 \
    || fail "send exit command failed" 

# Wait for master to exit
wait $SSH_PID
kill -0 $SSH_PID >/dev/null 2>&1 && fail "exit command failed"

# Enable compression and alternative kex for next conninfo test.
if $SSH -Q compression | grep zlib@openssh.com >/dev/null; then
	compression=yes
else
	compression=no
fi
echo compression $compression >>$OBJ/ssh_config
echo kexalgorithms curve25519-sha256 >>$OBJ/ssh_config
echo ciphers aes128-ctr >>$OBJ/ssh_config

# Restart master and test -O stop command with master using -N
verbose "test $tid: cmd stop"
trace "restart master, fork to background"
start_mux_master

verbose "test $tid: cmd conninfo algos"
conninfo=`${SSH} -F $OBJ/ssh_config -S $CTL -Oconninfo otherhost` \
     || fail "request remote forward failed"
if echo "$conninfo" | grep "kexalgorithm curve25519-sha256" >/dev/null &&
    echo "$conninfo" | grep "cipher aes128-ctr" >/dev/null; then
	trace "ok conninfo algos"
else
	fail "conninfo algos"
fi
if [ "$compression" = "yes" ]; then
	verbose "test $tid: cmd conninfo compression"
	if echo "$conninfo" | grep "compression zlib" >/dev/null &&
	    echo "$conninfo" | grep "compressed" >/dev/null; then
		trace "ok conninfo compression"
	else
		fail "conninfo compression"
	fi
fi

# start a long-running command then immediately request a stop
${SSH} -F $OBJ/ssh_config -S $CTL otherhost "sleep 10; exit 0" \
     >>$TEST_REGRESS_LOGFILE 2>&1 &
SLEEP_PID=$!
${SSH} -F$OBJ/ssh_config -S$CTL -Ostop otherhost >>$TEST_REGRESS_LOGFILE 2>&1 \
    || fail "send stop command failed"

# wait until both long-running command and master have exited.
wait $SLEEP_PID
[ $! != 0 ] || fail "waiting for concurrent command"
wait $SSH_PID
[ $! != 0 ] || fail "waiting for master stop"
kill -0 $SSH_PID >/dev/null 2>&1 && fatal "stop command failed"
SSH_PID="" # Already gone, so don't kill in cleanup

