#	$OpenBSD: sshfp-connect.sh,v 1.6 2026/07/11 09:59:10 dtucker Exp $
#	Placed in the Public Domain.

# This test requires external setup and thus is skipped unless
# TEST_SSH_SSHFP_DOMAIN is set.  It requires:
# 1) A DNSSEC-validating resolver such as unwind(8).
# 2) A DNSSEC-enabled domain, which TEST_SSH_SSHFP_DOMAIN points to,
#    containing he following SSHFP records with fingerprints from
#    rsa_openssh.pub in that domain that are expected to succeed:
#      rsa: valid sha1 and sha256 fingerprints.
#      rsa-sha{1,256}, : valid fingerprints for that type only.
#    and the following records that are expected to fail:
#      rsa-bad: invalid sha1 fingerprint and good sha256 fingerprint
#      rsa-sha{1,256}-bad: invalid fingerprints for that type only.

dnsfps='\
rsa IN SSHFP 1 1 99C79CC09F5F81069CC017CDF9552CFC94B3B929
rsa IN SSHFP 1 2 E30D6B9EB7A4DE495324E4D5870B8220577993EA6AF417E8E4A4F1C5BF01A9B6
rsa-sha1 IN SSHFP 1 1 99C79CC09F5F81069CC017CDF9552CFC94B3B929
rsa-sha256 IN SSHFP 1 2 E30D6B9EB7A4DE495324E4D5870B8220577993EA6AF417E8E4A4F1C5BF01A9B6
rsa-bad IN SSHFP 1 1 99C79CC09F5F81069CC017CDF9552CFC94B3B928
rsa-bad IN SSHFP 1 2 E30D6B9EB7A4DE495324E4D5870B8220577993EA6AF417E8E4A4F1C5BF01A9B6
rsa-sha1-bad IN SSHFP 1 1 99D79CC09F5F81069CC017CDF9552CFC94B3B929
rsa-sha256-bad IN SSHFP 1 2 E30D6B9EB7A4DE495324E4D5870B8220577993EA6AF417E8E4A4F1C5BF01A9B5'

tid="sshfp connect"

if [ -z "${TEST_SSH_SSHFP_DOMAIN}" ]; then
	skip "TEST_SSH_SSHFP_DOMAIN not set."
fi

# Check that the required DNS entries exist.
# This also primes any DNS caches and resolvers.
#
# It uses here documents instead of the more obvious "foo | while read"
# since the latter runs the loop inside a subshell and any variables set in it
# vanish when the subshell does.
while read line; do
	name=`echo "$line" | awk '{print $1}'`
	expected=`echo "$line" | awk '{print $4" "$5" "$6}'`
	# Ensure at least one result matches exactly
	matched=no
	while read result; do
		if [ "$result" = "$expected" ]; then
			matched=yes
		fi
	done <<EOD
`host -t sshfp "${name}.${TEST_SSH_SSHFP_DOMAIN}" | \
    awk '{print $5" "$6" "$7$8}'`
EOD
	if [ "$matched" = "no" ]; then
		fatal "$name.${TEST_SSH_SSHFP_DOMAIN} does not match required"
	fi
	trace "verified sshfp record '$name' -> '$expected'"
done <<EOD
$dnsfps
EOD
verbose "all required sshfp entries exist"

if $SSH -Q key-plain | grep ssh-rsa >/dev/null; then
	verbose "sshfp rsa"
	# Set RSA host key to match fingerprints above.
	mv $OBJ/sshd_proxy $OBJ/sshd_proxy.orig
	$SUDO cp $SRC/rsa_openssh.prv $OBJ/host.ssh-rsa
	$SUDO chmod 600 $OBJ/host.ssh-rsa
	sed -e "s|$OBJ/ssh-rsa|$OBJ/host.ssh-rsa|" \
	    $OBJ/sshd_proxy.orig > $OBJ/sshd_proxy

	# Zero out known hosts and key aliases to force use of SSHFP records.
	> $OBJ/known_hosts
	mv $OBJ/ssh_proxy $OBJ/ssh_proxy.orig
	sed -e "/HostKeyAlias.*localhost-with-alias/d" \
	    -e "/Hostname.*127.0.0.1/d" \
	    $OBJ/ssh_proxy.orig > $OBJ/ssh_proxy

	for n in rsa rsa-sha1 rsa-sha256; do
		trace "sshfp connect $n good fingerprint"
		host="${n}.dtucker.net"
		opts="-F $OBJ/ssh_proxy -oVerifyHostKeyDNS=yes"
		opts="$opts -oHostKeyAlgorithms=rsa-sha2-512,rsa-sha2-256"
		host="${n}.${TEST_SSH_SSHFP_DOMAIN}"
		SSH_CONNECTION=`${SSH} $opts $host 'echo $SSH_CONNECTION'`
		if [ $? -ne 0 ]; then
			fail "ssh sshfp connect failed"
		fi
		if [ "$SSH_CONNECTION" != "UNKNOWN 65535 UNKNOWN 65535" ]; then
			fail "bad SSH_CONNECTION: $SSH_CONNECTION"
		fi

		trace "sshfp connect $n bad fingerprint"
		host="${n}-bad.${TEST_SSH_SSHFP_DOMAIN}"
		if ${SSH} $opts ${host} true 2>/dev/null; then
			fail "sshfp-connect succeeded with bad SSHFP record"
		fi
	done
fi
