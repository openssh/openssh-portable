#
#  Copyright (c) 2017 Red Hat
#
#  Authors: Jakub Jelen <jjelen@redhat.com>
#
#  Permission to use, copy, modify, and distribute this software for any
#  purpose with or without fee is hereby granted, provided that the above
#  copyright notice and this permission notice appear in all copies.
#
#  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
#  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
#  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
#  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
#  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

tid="pkcs11 tests with soft token"

try_token_libs() {
	for _lib in "$@" ; do
		if test -f "$_lib" ; then
			verbose "Using token library $_lib"
			TEST_SSH_PKCS11="$_lib"
			return
		fi
	done
	echo "skipped: Unable to find PKCS#11 token library"
	exit 0
}

try_token_libs \
	/usr/local/lib/softhsm/libsofthsm2.so \
	/usr/lib64/pkcs11/libsofthsm2.so \
	/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so

TEST_SSH_PIN=1234
TEST_SSH_SOPIN=12345678
if [ "x$TEST_SSH_SSHPKCS11HELPER" != "x" ]; then
	SSH_PKCS11_HELPER="${TEST_SSH_SSHPKCS11HELPER}"
	export SSH_PKCS11_HELPER
fi

test -f "$TEST_SSH_PKCS11" || fatal "$TEST_SSH_PKCS11 does not exist"

# setup environment for softhsm token
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

# prevent ssh-agent from calling ssh-askpass
SSH_ASKPASS=/usr/bin/true
export SSH_ASKPASS
unset DISPLAY
# We need interactive access to test PKCS# since it prompts for PIN
sed -i 's/.*BatchMode.*//g' $OBJ/ssh_proxy

# start command w/o tty, so ssh accepts pin from stdin (from agent-pkcs11.sh)
notty() {
	perl -e 'use POSIX; POSIX::setsid();
	    if (fork) { wait; exit($? >> 8); } else { exec(@ARGV) }' "$@"
}

trace "generating keys"
ID1="02"
ID2="04"
RSA=${DIR}/RSA
EC=${DIR}/EC
openssl genpkey -algorithm rsa > $RSA
openssl pkcs8 -nocrypt -in $RSA |\
    softhsm2-util --slot "$slot" --label "SSH RSA Key $ID1" --id $ID1 \
	--pin "$TEST_SSH_PIN" --import /dev/stdin
openssl genpkey \
    -genparam \
    -algorithm ec \
    -pkeyopt ec_paramgen_curve:prime256v1 |\
    openssl genpkey \
    -paramfile /dev/stdin > $EC
openssl pkcs8 -nocrypt -in $EC |\
    softhsm2-util --slot "$slot" --label "SSH ECDSA Key $ID2" --id $ID2 \
	--pin "$TEST_SSH_PIN" --import /dev/stdin

trace "List the keys in the ssh-keygen with PKCS#11 URIs"
${SSHKEYGEN} -D ${TEST_SSH_PKCS11} > $OBJ/token_keys
if [ $? -ne 0 ]; then
	fail "FAIL: keygen fails to enumerate keys on PKCS#11 token"
fi
grep "pkcs11:" $OBJ/token_keys > /dev/null
if [ $? -ne 0 ]; then
	fail "FAIL: The keys from ssh-keygen do not contain PKCS#11 URI as a comment"
fi

# Set the ECDSA key to authorized keys
grep "ECDSA" $OBJ/token_keys > $OBJ/authorized_keys_$USER

trace "Simple connect with ssh (without PKCS#11 URI)"
echo ${TEST_SSH_PIN} | notty ${SSH} -I ${TEST_SSH_PKCS11} \
    -F $OBJ/ssh_proxy somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "FAIL: ssh connect with pkcs11 failed (exit code $r)"
fi

trace "Connect with PKCS#11 URI"
trace "  (ECDSA key should succeed)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
    -i "pkcs11:id=%${ID2}?module-path=${TEST_SSH_PKCS11}" somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "FAIL: ssh connect with PKCS#11 URI failed (exit code $r)"
fi

trace "  (RSA key should fail)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
     -i "pkcs11:id=%${ID1}?module-path=${TEST_SSH_PKCS11}" somehost exit 5
r=$?
if [ $r -eq 5 ]; then
	fail "FAIL: ssh connect with PKCS#11 URI succeeded (should fail)"
fi

trace "Connect with PKCS#11 URI including PIN should not prompt"
trace "  (ECDSA key should succeed)"
${SSH} -F $OBJ/ssh_proxy -i \
    "pkcs11:id=%${ID2}?module-path=${TEST_SSH_PKCS11}&pin-value=${TEST_SSH_PIN}" somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "FAIL: ssh connect with PKCS#11 URI failed (exit code $r)"
fi

trace "  (RSA key should fail)"
${SSH} -F $OBJ/ssh_proxy -i \
    "pkcs11:id=%${ID1}?module-path=${TEST_SSH_PKCS11}&pin-value=${TEST_SSH_PIN}" somehost exit 5
r=$?
if [ $r -eq 5 ]; then
	fail "FAIL: ssh connect with PKCS#11 URI succeeded (should fail)"
fi

trace "Connect with various filtering options in PKCS#11 URI"
trace "  (by object label, ECDSA should succeed)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
    -i "pkcs11:object=SSH%20ECDSA%20Key%2004?module-path=${TEST_SSH_PKCS11}" somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "FAIL: ssh connect with PKCS#11 URI failed (exit code $r)"
fi

trace "  (by object label, RSA key should fail)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
     -i "pkcs11:object=SSH%20RSA%20Key%2002?module-path=${TEST_SSH_PKCS11}" somehost exit 5
r=$?
if [ $r -eq 5 ]; then
	fail "FAIL: ssh connect with PKCS#11 URI succeeded (should fail)"
fi

trace "  (by token label, ECDSA key should succeed)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
    -i "pkcs11:id=%${ID2};token=token-slot-0?module-path=${TEST_SSH_PKCS11}" somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "FAIL: ssh connect with PKCS#11 URI failed (exit code $r)"
fi

trace "  (by wrong token label, should fail)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
     -i "pkcs11:token=token-slot-99?module-path=${TEST_SSH_PKCS11}" somehost exit 5
r=$?
if [ $r -eq 5 ]; then
	fail "FAIL: ssh connect with PKCS#11 URI succeeded (should fail)"
fi




trace "Test PKCS#11 URI specification in configuration files"
echo "IdentityFile \"pkcs11:id=%${ID2}?module-path=${TEST_SSH_PKCS11}\"" \
    >> $OBJ/ssh_proxy
trace "  (ECDSA key should succeed)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "FAIL: ssh connect with PKCS#11 URI in config failed (exit code $r)"
fi

# Set the RSA key as authorized
grep "RSA" $OBJ/token_keys > $OBJ/authorized_keys_$USER

trace "  (RSA key should fail)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy somehost exit 5
r=$?
if [ $r -eq 5 ]; then
	fail "FAIL: ssh connect with PKCS#11 URI in config succeeded (should fail)"
fi
sed -i -e "/IdentityFile/d" $OBJ/ssh_proxy

trace "Test PKCS#11 URI specification in configuration files with bogus spaces"
echo "IdentityFile \"    pkcs11:?module-path=${TEST_SSH_PKCS11}    \"" \
    >> $OBJ/ssh_proxy
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "FAIL: ssh connect with PKCS#11 URI with bogus spaces in config failed" \
	    "(exit code $r)"
fi
sed -i -e "/IdentityFile/d" $OBJ/ssh_proxy


trace "Combination of PKCS11Provider and PKCS11URI on commandline"
trace "  (RSA key should succeed)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
    -i "pkcs11:id=%${ID1}" -I ${TEST_SSH_PKCS11} somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "FAIL: ssh connect with PKCS#11 URI and provider combination" \
	    "failed (exit code $r)"
fi

trace "Regress: Missing provider in PKCS11URI option"
${SSH} -F $OBJ/ssh_proxy \
    -o IdentityFile=\"pkcs11:token=segfault\" somehost exit 5
r=$?
if [ $r -eq 139 ]; then
	fail "FAIL: ssh connect with missing provider_id from configuration option" \
	    "crashed (exit code $r)"
fi


trace "SSH Agent can work with PKCS#11 URI"
trace "start the agent"
eval `${SSHAGENT} -s` >  /dev/null

r=$?
if [ $r -ne 0 ]; then
	fail "could not start ssh-agent: exit code $r"
else
	trace "add whole provider to agent"
	echo ${TEST_SSH_PIN} | notty ${SSHADD} \
	    "pkcs11:?module-path=${TEST_SSH_PKCS11}" #> /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "FAIL: ssh-add failed with whole provider: exit code $r"
	fi

	trace " pkcs11 list via agent (all keys)"
	${SSHADD} -l > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "FAIL: ssh-add -l failed with whole provider: exit code $r"
	fi

	trace " pkcs11 connect via agent (all keys)"
	${SSH} -F $OBJ/ssh_proxy somehost exit 5
	r=$?
	if [ $r -ne 5 ]; then
		fail "FAIL: ssh connect failed with whole provider (exit code $r)"
	fi

	trace " remove pkcs11 keys (all keys)"
	${SSHADD} -d "pkcs11:?module-path=${TEST_SSH_PKCS11}" > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "FAIL: ssh-add -d failed with whole provider: exit code $r"
	fi

	trace "add only RSA key to the agent"
	echo ${TEST_SSH_PIN} | notty ${SSHADD} \
	    "pkcs11:id=%${ID1}?module-path=${TEST_SSH_PKCS11}" > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "FAIL ssh-add failed with RSA key: exit code $r"
	fi

	trace " pkcs11 connect via agent (RSA key)"
	${SSH} -F $OBJ/ssh_proxy somehost exit 5
	r=$?
	if [ $r -ne 5 ]; then
		fail "FAIL: ssh connect failed with RSA key (exit code $r)"
	fi

	trace " remove RSA pkcs11 key"
	${SSHADD} -d "pkcs11:id=%${ID1}?module-path=${TEST_SSH_PKCS11}" \
	    > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "FAIL: ssh-add -d failed with RSA key: exit code $r"
	fi

	trace "add only ECDSA key to the agent"
	echo ${TEST_SSH_PIN} | notty ${SSHADD} \
	    "pkcs11:id=%${ID2}?module-path=${TEST_SSH_PKCS11}" > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "FAIL: ssh-add failed with second key: exit code $r"
	fi

	trace " pkcs11 connect via agent (ECDSA key should fail)"
	${SSH} -F $OBJ/ssh_proxy somehost exit 5
	r=$?
	if [ $r -eq 5 ]; then
		fail "FAIL: ssh connect passed with ECDSA key (should fail)"
	fi

	trace "add also the RSA key to the agent"
	echo ${TEST_SSH_PIN} | notty ${SSHADD} \
	    "pkcs11:id=%${ID1}?module-path=${TEST_SSH_PKCS11}" > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "FAIL: ssh-add failed with first key: exit code $r"
	fi

	trace " remove ECDSA pkcs11 key"
	${SSHADD} -d "pkcs11:id=%${ID2}?module-path=${TEST_SSH_PKCS11}" \
	    > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add -d failed with ECDSA key: exit code $r"
	fi

	trace " remove already-removed pkcs11 key should fail"
	${SSHADD} -d "pkcs11:id=%${ID2}?module-path=${TEST_SSH_PKCS11}" \
	    > /dev/null 2>&1
	r=$?
	if [ $r -eq 0 ]; then
		fail "FAIL: ssh-add -d passed with non-existing key (should fail)"
	fi

	trace " pkcs11 connect via agent (the RSA key should be still usable)"
	${SSH} -F $OBJ/ssh_proxy somehost exit 5
	r=$?
	if [ $r -ne 5 ]; then
		fail "ssh connect failed with RSA key (after removing ECDSA): exit code $r"
	fi

	trace "kill agent"
	${SSHAGENT} -k > /dev/null
fi
