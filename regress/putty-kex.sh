#	$OpenBSD: putty-kex.sh,v 1.6 2021/08/31 06:13:23 dtucker Exp $
#	Placed in the Public Domain.

tid="putty KEX"

if test "x$REGRESS_INTEROP_PUTTY" != "xyes" ; then
	fatal "putty interop tests not enabled"
fi

# Re-enable ssh-rsa on older PuTTY versions.
oldver="`${PLINK} --version | awk '/plink: Release/{if ($3<0.76)print "yes"}'`"
if [ "x$oldver" = "xyes" ]; then
	echo "HostKeyalgorithms +ssh-rsa" >> sshd_config
fi

for k in dh-gex-sha1 dh-group1-sha1 dh-group14-sha1 ecdh ; do
	verbose "$tid: kex $k"
	cp ${OBJ}/.putty/sessions/localhost_proxy \
	    ${OBJ}/.putty/sessions/kex_$k
	echo "KEX=$k" >> ${OBJ}/.putty/sessions/kex_$k

	env HOME=$PWD ${PLINK} -load kex_$k -batch -i ${OBJ}/putty.rsa2 true
	if [ $? -ne 0 ]; then
		fail "KEX $k failed"
	fi
done

