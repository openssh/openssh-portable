#	$OpenBSD: dynamic-forward.sh,v 1.1 2003/06/26 14:23:10 markus Exp $
#	Placed in the Public Domain.

tid="dynamic forwarding"

PORT=4242
FWDPORT=4243

if [ -x `which nc` ] && nc -h 2>&1 | grep "x proxy address" >/dev/null; then
	proxycmd="nc -x 127.0.0.1:$FWDPORT -X"
elif [ -x `which connect` ]; then
	proxycmd="connect -S 127.0.0.1:$FWDPORT -"
else
	echo "skipped (no suitable ProxyCommand found)"
	exit 0
fi
trace "will use ProxyCommand $proxycmd"

start_sshd

for p in 1 2; do
  for s in 4; do
    for h in 127.0.0.1 localhost; do
	trace "testing ssh protocol $p socks version $s host $h"
	trace "start dynamic forwarding, fork to background"
	${SSH} -$p -F $OBJ/ssh_config -f -D $FWDPORT somehost sleep 10

	trace "transfer over forwarded channel and check result"
	${SSH} -F $OBJ/ssh_config -o "ProxyCommand ${proxycmd}${s} $h $PORT" \
		somehost cat /bin/ls > $OBJ/ls.copy
	test -f $OBJ/ls.copy	 || fail "failed copy /bin/ls"
	cmp /bin/ls $OBJ/ls.copy || fail "corrupted copy of /bin/ls"

	sleep 10
    done
  done
done
