#	$OpenBSD: putty-ciphers.sh,v 1.8 2021/08/31 06:13:23 dtucker Exp $
#	Placed in the Public Domain.

tid="putty ciphers"

if test "x$REGRESS_INTEROP_PUTTY" != "xyes" ; then
	fatal "putty interop tests not enabled"
fi

# Re-enable ssh-rsa on older PuTTY versions.
oldver="`${PLINK} --version | awk '/plink: Release/{if ($3<0.76)print "yes"}'`"
if [ "x$oldver" = "xyes" ]; then
	echo "HostKeyalgorithms +ssh-rsa" >> sshd_config
fi

for c in aes 3des aes128-ctr aes192-ctr aes256-ctr chacha20 ; do
	verbose "$tid: cipher $c"
	cp ${OBJ}/.putty/sessions/localhost_proxy \
	    ${OBJ}/.putty/sessions/cipher_$c
	echo "Cipher=$c" >> ${OBJ}/.putty/sessions/cipher_$c

	rm -f ${COPY}
	env HOME=$PWD ${PLINK} -load cipher_$c -batch -i ${OBJ}/putty.rsa2 \
	    cat ${DATA} > ${COPY}
	if [ $? -ne 0 ]; then
		fail "ssh cat $DATA failed"
	fi
	cmp ${DATA} ${COPY}		|| fail "corrupted copy"
done
rm -f ${COPY}

