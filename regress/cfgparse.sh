#	$OpenBSD: cfgparse.sh,v 1.11 2026/07/21 23:43:15 dtucker Exp $
#	Placed in the Public Domain.

tid="sshd config parse"

# This is a reasonable proxy for IPv6 support.
if ! config_defined HAVE_STRUCT_IN6_ADDR ; then
       SKIP_IPV6=yes

# Some variables for the IPv6 addresses.  This allows Portable to skip
# these on platorms without IPv6 support without having diffs within the
# tests themselves.
LISTENADDRESS_IPV6_LOOPBACK="listenaddress ::1"
LISTENADDRESS_IPV6_LOOPBACK_1234="listenaddress [::1]:1234"
LISTENADDRESS_IPV6_LOOPBACK_5678="listenaddress [::1]:5678"

fi

# We need to use the keys generated for the regression test because sshd -T
# will fail if we're not running with SUDO (no permissions for real keys) or
# if we are running tests on a system that has never had sshd installed
# because the keys won't exist.

grep "HostKey " $OBJ/sshd_config > $OBJ/sshd_config_minimal
SSHD_KEYS="`cat $OBJ/sshd_config_minimal`"

verbose "reparse minimal config"
($SUDO ${SSHD} -T -f $OBJ/sshd_config_minimal >$OBJ/sshd_config.1 &&
 $SUDO ${SSHD} -T -f $OBJ/sshd_config.1 >$OBJ/sshd_config.2 &&
 diff $OBJ/sshd_config.1 $OBJ/sshd_config.2) || fail "reparse minimal config"

verbose "reparse regress config"
($SUDO ${SSHD} -T -f $OBJ/sshd_config >$OBJ/sshd_config.1 &&
 $SUDO ${SSHD} -T -f $OBJ/sshd_config.1 >$OBJ/sshd_config.2 &&
 diff $OBJ/sshd_config.1 $OBJ/sshd_config.2) || fail "reparse regress config"

verbose "listenaddress order"
# expected output
egrep -v '^$' > $OBJ/sshd_config.0 <<EOD
listenaddress 1.2.3.4:1234
listenaddress 1.2.3.4:5678
$LISTENADDRESS_IPV6_LOOPBACK_1234
$LISTENADDRESS_IPV6_LOOPBACK_5678
EOD

# test input sets.  should all result in the output above.
# test 1: addressfamily and port first
egrep -v '^$' > $OBJ/sshd_config.1 <<EOD
${SSHD_KEYS}
addressfamily any
port 1234
port 5678
listenaddress 1.2.3.4
$LISTENADDRESS_IPV6_LOOPBACK
EOD
($SUDO ${SSHD} -T -f $OBJ/sshd_config.1 | \
 grep -i '^listenaddress ' >$OBJ/sshd_config.2 &&
 diff -i $OBJ/sshd_config.0 $OBJ/sshd_config.2) || \
 fail "listenaddress order 1"

# test 2: listenaddress first
cat > $OBJ/sshd_config.1 <<EOD
${SSHD_KEYS}
listenaddress 1.2.3.4
$LISTENADDRESS_IPV6_LOOPBACK
port 1234
port 5678
addressfamily any
EOD
($SUDO ${SSHD} -T -f $OBJ/sshd_config.1 | \
 grep -i '^ListenAddress ' >$OBJ/sshd_config.2 &&
 diff -i $OBJ/sshd_config.0 $OBJ/sshd_config.2) || \
 fail "listenaddress order 2"

# Check idempotence of MaxStartups
verbose "maxstartups idempotent"
echo "maxstartups 1:2:3" > $OBJ/sshd_config.0
cat > $OBJ/sshd_config.1 <<EOD
${SSHD_KEYS}
MaxStartups 1:2:3
MaxStartups 8:16:32
EOD
($SUDO ${SSHD} -T -f $OBJ/sshd_config.1 | \
 grep -i '^maxstartups ' >$OBJ/sshd_config.2 &&
 diff -i $OBJ/sshd_config.0 $OBJ/sshd_config.2) || \
 fail "maxstartups idempotence"

# cleanup
rm -f $OBJ/sshd_config.[012]
