#	$OpenBSD: try-ciphers.sh,v 1.21 2013/11/07 02:48:38 dtucker Exp $
#	Placed in the Public Domain.

tid="try ciphers"

for c in `${SSH} -Q cipher`; do
	n=0
	for m in `${SSH} -Q mac`; do
		trace "proto 2 cipher $c mac $m"
		verbose "test $tid: proto 2 cipher $c mac $m"
		${SSH} -F $OBJ/ssh_proxy -2 -m $m -c $c somehost true
		if [ $? -ne 0 ]; then
			fail "ssh -2 failed with mac $m cipher $c"
		fi
		# No point trying all MACs for GCM since they are ignored.
		case $c in
		aes*-gcm@openssh.com)	test $n -gt 0 && break;;
		esac
		n=`expr $n + 1`
	done
done

ciphers="3des blowfish"
for c in $ciphers; do
	trace "proto 1 cipher $c"
	verbose "test $tid: proto 1 cipher $c"
	${SSH} -F $OBJ/ssh_proxy -1 -c $c somehost true
	if [ $? -ne 0 ]; then
		fail "ssh -1 failed with cipher $c"
	fi
done

