#	$OpenBSD: dynamic-forward.sh,v 1.15 2023/01/06 08:50:33 dtucker Exp $
#	Placed in the Public Domain.

tid="dynamic forwarding"

FWDPORT=`expr $PORT + 1`

cp $OBJ/ssh_config $OBJ/ssh_config.orig

proxycmd="$OBJ/netcat -x 127.0.0.1:$FWDPORT -X"
trace "will use ProxyCommand $proxycmd"

# This is a reasonable proxy for IPv6 support.
if ! config_defined HAVE_STRUCT_IN6_ADDR ; then
	SKIP_IPV6=yes
fi

start_ssh() {
	direction="$1"
	arg="$2"
	n=0
	error="1"
	trace "start dynamic -$direction forwarding, fork to background"
	(cat $OBJ/ssh_config.orig ; echo "$arg") > $OBJ/ssh_config
	while [ "$error" -ne 0 -a "$n" -lt 3 ]; do
		n=`expr $n + 1`
		${SSH} -F $OBJ/ssh_config -f -vvv -E$TEST_SSH_LOGFILE \
		    -$direction $FWDPORT -oExitOnForwardFailure=yes \
		    somehost exec sh -c \
			\'"echo \$\$ > $OBJ/remote_pid; exec sleep 444"\'
		error=$?
		if [ "$error" -ne 0 ]; then
			trace "forward failed attempt $n err $error"
			sleep $n
		fi
	done
	if [ "$error" -ne 0 ]; then
		fatal "failed to start dynamic forwarding"
	fi
}

stop_ssh() {
	if [ -f $OBJ/remote_pid ]; then
		remote=`cat $OBJ/remote_pid`
		trace "terminate remote shell, pid $remote"
		if [ $remote -gt 1 ]; then
			kill -HUP $remote
		fi
	else
		fail "no pid file: $OBJ/remote_pid"
	fi
}

check_socks() {
	direction=$1
	expect_success=$2
	for s in 4 5; do
	    for h in 127.0.0.1 localhost; do
		trace "testing ssh socks version $s host $h (-$direction)"
		${SSH} -F $OBJ/ssh_config \
			-o "ProxyCommand ${proxycmd}${s} $h $PORT 2>/dev/null" \
			somehost cat ${DATA} > ${COPY}
		r=$?
		if [ "x$expect_success" = "xY" ] ; then
			if [ $r -ne 0 ] ; then
				fail "ssh failed with exit status $r"
			fi
			test -f ${COPY}	 || fail "failed copy ${DATA}"
			cmp ${DATA} ${COPY} || fail "corrupted copy of ${DATA}"
		elif [ $r -eq 0 ] ; then
			fail "ssh unexpectedly succeeded"
		fi
	    done
	done
}

start_sshd

for d in D R; do
	verbose "test -$d forwarding"
	start_ssh $d
	check_socks $d Y
	stop_ssh
	test "x$d" = "xR" || continue
	
	# Test PermitRemoteOpen
	verbose "PermitRemoteOpen=any"
	start_ssh $d PermitRemoteOpen=any
	check_socks $d Y
	stop_ssh

	verbose "PermitRemoteOpen=none"
	start_ssh $d PermitRemoteOpen=none
	check_socks $d N
	stop_ssh

	verbose "PermitRemoteOpen=explicit"
	permit="127.0.0.1:$PORT [::1]:$PORT localhost:$PORT"
	test -z "$SKIP_IPV6" || permit="127.0.0.1:$PORT localhost:$PORT"
	start_ssh $d PermitRemoteOpen="$permit"
	check_socks $d Y
	stop_ssh

	verbose "PermitRemoteOpen=disallowed"
	permit="127.0.0.1:1 [::1]:1 localhost:1"
	test -z "$SKIP_IPV6" || permit="127.0.0.1:1 localhost:1"
	start_ssh $d PermitRemoteOpen="$permit"
	check_socks $d N
	stop_ssh
done
