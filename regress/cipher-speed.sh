#	$OpenBSD: cipher-speed.sh,v 1.10 2013/11/07 02:48:38 dtucker Exp $
#	Placed in the Public Domain.

tid="cipher speed"

getbytes ()
{
	sed -n -e '/transferred/s/.*secs (\(.* bytes.sec\).*/\1/p' \
	    -e '/copied/s/.*s, \(.* MB.s\).*/\1/p'
}

tries="1 2"

for c in `${SSH} -Q cipher`; do n=0; for m in `${SSH} -Q mac`; do
	trace "proto 2 cipher $c mac $m"
	for x in $tries; do
		printf "%-60s" "$c/$m:"
		( ${SSH} -o 'compression no' \
			-F $OBJ/ssh_proxy -2 -m $m -c $c somehost \
			exec sh -c \'"dd of=/dev/null obs=32k"\' \
		< ${DATA} ) 2>&1 | getbytes

		if [ $? -ne 0 ]; then
			fail "ssh -2 failed with mac $m cipher $c"
		fi
	done
	# No point trying all MACs for GCM since they are ignored.
	case $c in
	aes*-gcm@openssh.com)	test $n -gt 0 && break;;
	esac
	n=`expr $n + 1`
done; done

ciphers="3des blowfish"
for c in $ciphers; do
	trace "proto 1 cipher $c"
	for x in $tries; do
		printf "%-60s" "$c:"
		( ${SSH} -o 'compression no' \
			-F $OBJ/ssh_proxy -1 -c $c somehost \
			exec sh -c \'"dd of=/dev/null obs=32k"\' \
		< ${DATA} ) 2>&1 | getbytes
		if [ $? -ne 0 ]; then
			fail "ssh -1 failed with cipher $c"
		fi
	done
done
