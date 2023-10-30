#	$OpenBSD: agent-pkcs11.sh,v 1.12 2023/10/30 17:32:00 djm Exp $
#	Placed in the Public Domain.

tid="pkcs11 agent test"

# Find a PKCS#11 library.
p11_find_lib() {
	TEST_SSH_PKCS11=""
	for _lib in "$@" ; do
		if test -f "$_lib" ; then
			TEST_SSH_PKCS11="$_lib"
			return
		fi
	done
}

# Perform PKCS#11 setup: prepares a softhsm2 token configuration, generated
# keys and loads them into the virtual token.
PKCS11_OK=
export PKCS11_OK
p11_setup() {
	p11_find_lib \
		/usr/local/lib/softhsm/libsofthsm2.so \
		/usr/lib64/pkcs11/libsofthsm2.so \
		/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
	test -z "$TEST_SSH_PKCS11" && return 1
	verbose "using token library $TEST_SSH_PKCS11"
	TEST_SSH_PIN=1234
	TEST_SSH_SOPIN=12345678
	if [ "x$TEST_SSH_SSHPKCS11HELPER" != "x" ]; then
		SSH_PKCS11_HELPER="${TEST_SSH_SSHPKCS11HELPER}"
		export SSH_PKCS11_HELPER
	fi

	# setup environment for softhsm2 token
	DIR=$OBJ/SOFTHSM
	rm -rf $DIR
	TOKEN=$DIR/tokendir
	mkdir -p $TOKEN
	SOFTHSM2_CONF=$DIR/softhsm2.conf
	export SOFTHSM2_CONF
	cat > $SOFTHSM2_CONF << EOF
# SoftHSM v2 configuration file
directories.tokendir = ${TOKEN}
objectstore.backend = file
# ERROR, WARNING, INFO, DEBUG
log.level = DEBUG
# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false
EOF
	out=$(softhsm2-util --init-token --free --label token-slot-0 --pin "$TEST_SSH_PIN" --so-pin "$TEST_SSH_SOPIN")
	slot=$(echo -- $out | sed 's/.* //')
	trace "generating keys"
	# RSA key
	RSA=${DIR}/RSA
	RSAP8=${DIR}/RSAP8
	$OPENSSL_BIN genpkey -algorithm rsa > $RSA 2>/dev/null || \
	    fatal "genpkey RSA fail"
	$OPENSSL_BIN pkcs8 -nocrypt -in $RSA > $RSAP8 || fatal "pkcs8 RSA fail"
	softhsm2-util --slot "$slot" --label 01 --id 01 --pin "$TEST_SSH_PIN" \
	    --import $RSAP8 >/dev/null || fatal "softhsm import RSA fail"
	chmod 600 $RSA
	ssh-keygen -y -f $RSA > ${RSA}.pub
	# ECDSA key
	ECPARAM=${DIR}/ECPARAM
	EC=${DIR}/EC
	ECP8=${DIR}/ECP8
	$OPENSSL_BIN genpkey -genparam -algorithm ec \
	    -pkeyopt ec_paramgen_curve:prime256v1 > $ECPARAM || \
	    fatal "param EC fail"
	$OPENSSL_BIN genpkey -paramfile $ECPARAM > $EC || \
	    fatal "genpkey EC fail"
	$OPENSSL_BIN pkcs8 -nocrypt -in $EC > $ECP8 || fatal "pkcs8 EC fail"
	softhsm2-util --slot "$slot" --label 02 --id 02 --pin "$TEST_SSH_PIN" \
	    --import $ECP8 >/dev/null || fatal "softhsm import EC fail"
	chmod 600 $EC
	ssh-keygen -y -f $EC > ${EC}.pub
	# Prepare askpass script to load PIN.
	PIN_SH=$DIR/pin.sh
	cat > $PIN_SH << EOF
#!/bin/sh
echo "${TEST_SSH_PIN}"
EOF
	chmod 0700 "$PIN_SH"
	PKCS11_OK=yes
	return 0
}

# Peforms ssh-add with the right token PIN.
p11_ssh_add() {
	env SSH_ASKPASS="$PIN_SH" SSH_ASKPASS_REQUIRE=force ${SSHADD} "$@"
}

p11_setup || skip "No PKCS#11 library found"

trace "start agent"
eval `${SSHAGENT} ${EXTRA_AGENT_ARGS} -s` > /dev/null
r=$?
if [ $r -ne 0 ]; then
	fail "could not start ssh-agent: exit code $r"
else
	trace "add pkcs11 key to agent"
	p11_ssh_add -s ${TEST_SSH_PKCS11} > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add -s failed: exit code $r"
	fi

	trace "pkcs11 list via agent"
	${SSHADD} -l > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add -l failed: exit code $r"
	fi

	for k in $RSA $EC; do
		trace "testing $k"
		pub=$(cat $k.pub)
		${SSHADD} -L | grep -q "$pub" || \
			fail "key $k missing in ssh-add -L"
		${SSHADD} -T $k.pub || fail "ssh-add -T with $k failed"

		# add to authorized keys
		cat $k.pub > $OBJ/authorized_keys_$USER
		trace "pkcs11 connect via agent ($k)"
		${SSH} -F $OBJ/ssh_proxy somehost exit 5
		r=$?
		if [ $r -ne 5 ]; then
			fail "ssh connect failed (exit code $r)"
		fi
	done

	trace "remove pkcs11 keys"
	p11_ssh_add -e ${TEST_SSH_PKCS11} > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add -e failed: exit code $r"
	fi

	trace "kill agent"
	${SSHAGENT} -k > /dev/null
fi
