#	$OpenBSD: integrity.sh,v 1.1 2012/12/11 22:42:11 markus Exp $
#	Placed in the Public Domain.

tid="integrity"

# start at byte 2300 (i.e. after kex) and corrupt at different offsets
# XXX the test hangs if we modify the low bytes of the packet length
# XXX and ssh tries to read...
tries=10
startoffset=2300
macs="hmac-sha1 hmac-md5 umac-64@openssh.com umac-128@openssh.com
	hmac-sha1-96 hmac-md5-96 hmac-sha2-256 hmac-sha2-512
	hmac-sha1-etm@openssh.com hmac-md5-etm@openssh.com
	umac-64-etm@openssh.com umac-128-etm@openssh.com
	hmac-sha1-96-etm@openssh.com hmac-md5-96-etm@openssh.com
	hmac-sha2-256-etm@openssh.com hmac-sha2-512-etm@openssh.com"

# sshd-command for proxy (see test-exec.sh)
cmd="sh ${SRC}/sshd-log-wrapper.sh ${SSHD} ${TEST_SSH_LOGFILE} -i -f $OBJ/sshd_proxy"

for m in $macs; do
	trace "test $tid: mac $m"
	elen=0
	epad=0
	emac=0
	ecnt=0
	skip=0
	for off in $(jot $tries $startoffset); do
		if [ $((skip--)) -gt 0 ]; then
			# avoid modifying the high bytes of the length
			continue
		fi
		# modify output from sshd at offset $off
		pxy="proxycommand=$cmd | $OBJ/modpipe -m xor:$off:1"
		output=$(${SSH} -m $m -2F $OBJ/ssh_proxy -o "$pxy" \
		    999.999.999.999 true 2>&1)
		if [ $? -eq 0 ]; then
			fail "ssh -m $m succeeds with bit-flip at $off"
		fi
		ecnt=$((ecnt+1))
		output=$(echo $output | tr -s '\r\n' '.')
		verbose "test $tid: $m @$off $output"
		case "$output" in
		Bad?packet*)	elen=$((elen+1)); skip=2;;
		Corrupted?MAC*) emac=$((emac+1)); skip=0;;
		padding*)	epad=$((epad+1)); skip=0;;
		*)		fail "unexpected error mac $m at $off";;
		esac
	done
	verbose "test $tid: $ecnt errors: mac $emac padding $epad length $elen"
	if [ $emac -eq 0 ]; then
		fail "$m: no mac errors"
	fi
	expect=$((ecnt-epad-elen))
	if [ $emac -ne $expect ]; then
		fail "$m: expected $expect mac errors, got $emac"
	fi
done
