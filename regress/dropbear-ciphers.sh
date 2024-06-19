#	$OpenBSD: dropbear-ciphers.sh,v 1.2 2024/06/19 10:15:51 dtucker Exp $
#	Placed in the Public Domain.

tid="dropbear ciphers"

if test "x$REGRESS_INTEROP_DROPBEAR" != "xyes" ; then
	skip "dropbear interop tests not enabled"
fi

# Enable all support algorithms
algs=`$SSH -Q key-sig | tr '\n' ,`
cat >>$OBJ/sshd_proxy <<EOD
PubkeyAcceptedAlgorithms $algs
HostkeyAlgorithms $algs
EOD

ciphers=`$DBCLIENT -c help 2>&1 | awk '/ ciphers: /{print $4}' | tr ',' ' '`
if [ -z "$ciphers" ]; then
	trace dbclient query ciphers failed, making assumptions.
	ciphers="chacha20-poly1305@openssh.com aes128-ctr aes256-ctr"
fi
macs=`$DBCLIENT -m help 2>&1 | awk '/ MACs: /{print $4}' | tr ',' ' '`
if [ -z "$macs" ]; then
	trace dbclient query macs failed, making assumptions.
	macs="hmac-sha1 hmac-sha2-256"
fi
keytype=`(cd $OBJ/.dropbear && ls id_*)`

for c in $ciphers ; do
  for m in $macs; do
    for kt in $keytype; do
	verbose "$tid: cipher $c mac $m kt $kt"
	rm -f ${COPY}
	env HOME=$OBJ dbclient -y -i $OBJ/.dropbear/$kt 2>$OBJ/dbclient.log \
	    -c $c -m $m -J "$OBJ/ssh_proxy.sh" somehost cat ${DATA} > ${COPY}
	if [ $? -ne 0 ]; then
		fail "ssh cat $DATA failed"
	fi
	cmp ${DATA} ${COPY}		|| fail "corrupted copy"
    done
  done
done
rm -f ${COPY}
