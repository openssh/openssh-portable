#	$OpenBSD: cert-userkey.sh,v 1.1 2010/02/26 20:33:21 djm Exp $
#	Placed in the Public Domain.

tid="certified user keys"

rm -f $OBJ/authorized_keys_$USER $OBJ/user_ca_key* $OBJ/cert_user_key*
cp $OBJ/sshd_proxy $OBJ/sshd_proxy_bak

# Create a CA key and add it to authorized_keys
${SSHKEYGEN} -q -N '' -t rsa  -f $OBJ/user_ca_key ||\
	fail "ssh-keygen of user_ca_key failed"
(
	echo -n 'cert-authority '
	cat $OBJ/user_ca_key.pub
) > $OBJ/authorized_keys_$USER

# Generate and sign user keys
for ktype in rsa dsa ; do 
	verbose "$tid: sign user ${ktype} cert"
	${SSHKEYGEN} -q -N '' -t ${ktype} \
	    -f $OBJ/cert_user_key_${ktype} || \
		fail "ssh-keygen of cert_user_key_${ktype} failed"
	${SSHKEYGEN} -q -s $OBJ/user_ca_key -I \
	    "regress user key for $USER" \
	    -n $USER $OBJ/cert_user_key_${ktype} ||
		fail "couldn't sign cert_user_key_${ktype}"

done

# Basic connect tests
for privsep in yes no ; do
	for ktype in rsa dsa ; do 
		verbose "$tid: user ${ktype} cert connect privsep $privsep"
		(
			cat $OBJ/sshd_proxy_bak
			echo "UsePrivilegeSeparation $privsep"
		) > $OBJ/sshd_proxy

		${SSH} -2i $OBJ/cert_user_key_${ktype} -F $OBJ/ssh_proxy \
		    somehost true
		if [ $? -ne 0 ]; then
			fail "ssh cert connect failed"
		fi
	done
done

verbose "$tid: ensure CA key does not authenticate user"
${SSH} -2i $OBJ/user_ca_key -F $OBJ/ssh_proxy somehost true >/dev/null 2>&1
if [ $? -eq 0 ]; then
	fail "ssh cert connect with CA key succeeded unexpectedly"
fi

test_one() {
	ident=$1
	result=$2
	sign_opts=$3
	
	verbose "$tid: test user cert connect $ident expect $result"

	${SSHKEYGEN} -q -s $OBJ/user_ca_key -I "regress user key for $USER" \
	    $sign_opts \
	    $OBJ/cert_user_key_rsa ||
		fail "couldn't sign cert_user_key_rsa"

	${SSH} -2i $OBJ/cert_user_key_rsa -F $OBJ/ssh_proxy \
	    somehost true >/dev/null 2>&1
	rc=$?
	if [ "x$result" = "xsuccess" ] ; then
		if [ $rc -ne 0 ]; then
			fail "ssh cert connect $ident failed unexpectedly"
		fi
	else
		if [ $rc -eq 0 ]; then
			fail "ssh cert connect $ident succeeded unexpectedly"
		fi
	fi
	cleanup
}

test_one "host-certificate"	failure "-h"
test_one "empty principals"	success ""
test_one "wrong principals"	failure "-n foo"
test_one "cert not yet valid"	failure "-V20200101:20300101"
test_one "cert expired"		failure "-V19800101:19900101"
test_one "cert valid interval"	success "-V-1w:+2w"
test_one "wrong source-address"	failure "-Osource-address=10.0.0.0/8"
test_one "force-command"	failure "-Oforce-command=false"

rm -f $OBJ/authorized_keys_$USER $OBJ/user_ca_key* $OBJ/cert_user_key*
