#	$OpenBSD: keygen-convert.sh,v 1.4 2021/07/23 05:07:16 dtucker Exp $
#	Placed in the Public Domain.

tid="convert keys"

ecdsa=0
types=""
for i in ${SSH_KEYTYPES}; do
	case "$i" in
		ssh-dss)	types="$types dsa" ;;
		ssh-rsa)	types="$types rsa" ;;
		ssh-ed25519)	types="$types ed25519" ;;
		ecdsa-sha2-*)	ecdsa=1 ;;
	esac
done
if [ "x$ecdsa" = "x1" ]; then
	types="$types ecdsa"
fi

cat > $OBJ/askpass <<EOD
#!/bin/sh
echo hunter2
EOD
chmod u+x $OBJ/askpass

for t in $types; do
	# generate user key for agent
	trace "generating $t key"
	rm -f $OBJ/$t-key
	${SSHKEYGEN} -q -N "" -t $t -f $OBJ/$t-key

	trace "export $t private to rfc4716 public"
	${SSHKEYGEN} -q -e -f $OBJ/$t-key >$OBJ/$t-key-rfc || \
	    fail "export $t private to rfc4716 public"

	trace "export $t public to rfc4716 public"
	${SSHKEYGEN} -q -e -f $OBJ/$t-key.pub >$OBJ/$t-key-rfc.pub || \
	    fail "$t public to rfc4716 public"

	cmp $OBJ/$t-key-rfc $OBJ/$t-key-rfc.pub || \
	    fail "$t rfc4716 exports differ between public and private"

	trace "import $t rfc4716 public"
	${SSHKEYGEN} -q -i -f $OBJ/$t-key-rfc >$OBJ/$t-rfc-imported || \
	    fail "$t import rfc4716 public"

	cut -f1,2 -d " " $OBJ/$t-key.pub >$OBJ/$t-key-nocomment.pub
	cmp $OBJ/$t-key-nocomment.pub $OBJ/$t-rfc-imported || \
	    fail "$t imported differs from original"

	trace "set passphrase $t"
	${SSHKEYGEN} -q -p -P '' -N 'hunter2' -f $OBJ/$t-key >/dev/null || \
	    fail "$t set passphrase failed"

	trace "export $t to public with passphrase"
	SSH_ASKPASS=$OBJ/askpass SSH_ASKPASS_REQUIRE=force \
	    ${SSHKEYGEN} -y -f $OBJ/$t-key >$OBJ/$t-key-nocomment.pub
	cmp $OBJ/$t-key.pub $OBJ/$t-key-nocomment.pub || \
	    fail "$t exported pubkey differs from generated"

	rm -f $OBJ/$t-key $OBJ/$t-key.pub $OBJ/$t-key-rfc $OBJ/$t-key-rfc.pub \
	    $OBJ/$t-rfc-imported $OBJ/$t-key-nocomment.pub
done
