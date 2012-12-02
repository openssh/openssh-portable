#	$OpenBSD: keys-command.sh,v 1.1 2012/11/22 22:49:30 djm Exp $
#	Placed in the Public Domain.

tid="authorized keys from command"

if test -z "$SUDO" ; then
	echo "skipped (SUDO not set)"
	echo "need SUDO to create file in /var/run, test won't work without"
	exit 0
fi

# Establish a AuthorizedKeysCommand in /var/run where it will have
# acceptable directory permissions.
KEY_COMMAND="/var/run/keycommand_${LOGNAME}"
cat << _EOF | $SUDO sh -c "cat > '$KEY_COMMAND'"
#!/bin/sh
test "x\$1" -ne "x${LOGNAME}" && exit 1
exec cat "$OBJ/authorized_keys_${LOGNAME}"
_EOF
$SUDO chmod 0755 "$KEY_COMMAND"

cp $OBJ/sshd_proxy $OBJ/sshd_proxy.bak
(
	grep -vi AuthorizedKeysFile $OBJ/sshd_proxy.bak
	echo AuthorizedKeysFile none
	echo AuthorizedKeysCommand $KEY_COMMAND
	echo AuthorizedKeysCommandUser ${LOGNAME}
) > $OBJ/sshd_proxy

${SSH} -F $OBJ/ssh_proxy somehost true
if [ $? -ne 0 ]; then
	fail "connect failed"
fi
