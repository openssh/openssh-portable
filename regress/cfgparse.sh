#	$OpenBSD: cfgparse.sh,v 1.2 2015/04/29 05:23:27 dtucker Exp $
#	Placed in the Public Domain.

tid="config parse"

verbose "reparse default config"
($SUDO ${SSHD} -T -f /dev/null >$OBJ/sshd_config.1 &&
 $SUDO ${SSHD} -T -f $OBJ/sshd_config.1 >$OBJ/sshd_config.2 &&
 diff $OBJ/sshd_config.1 $OBJ/sshd_config.2) || fail "reparse default config"

verbose "reparse regress config"
($SUDO ${SSHD} -T -f $OBJ/sshd_config >$OBJ/sshd_config.1 &&
 $SUDO ${SSHD} -T -f $OBJ/sshd_config.1 >$OBJ/sshd_config.2 &&
 diff $OBJ/sshd_config.1 $OBJ/sshd_config.2) || fail "reparse regress config"

verbose "listenaddress order"
# expected output
cat > $OBJ/sshd_config.0 <<EOD
listenaddress 1.2.3.4:1234
listenaddress 1.2.3.4:5678
listenaddress [::1]:1234
listenaddress [::1]:5678
EOD
# test input sets.  should all result in the output above.
# test 1: addressfamily and port first
cat > $OBJ/sshd_config.1 <<EOD
addressfamily any
port 1234
port 5678
listenaddress 1.2.3.4
listenaddress ::1
EOD
($SUDO ${SSHD} -T -f $OBJ/sshd_config.1 | \
 grep 'listenaddress ' >$OBJ/sshd_config.2 &&
 diff -u $OBJ/sshd_config.0 $OBJ/sshd_config.2) || \
 fail "listenaddress order 1"
# test 2: listenaddress first
cat > $OBJ/sshd_config.1 <<EOD
listenaddress 1.2.3.4
listenaddress ::1
port 1234
port 5678
addressfamily any
EOD
($SUDO ${SSHD} -T -f $OBJ/sshd_config.1 | \
 grep 'listenaddress ' >$OBJ/sshd_config.2 &&
 diff -u $OBJ/sshd_config.0 $OBJ/sshd_config.2) || \
 fail "listenaddress order 2"

# cleanup
rm -f $OBJ/sshd_config.[012]
