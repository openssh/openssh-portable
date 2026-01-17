#	$OpenBSD: connect-uri.sh,v 1.1 2017/10/24 19:33:32 millert Exp $
#	Placed in the Public Domain.

tid="uri connect"

# Remove Port and User from ssh_config, we want to rely on the URI
cp $OBJ/ssh_config $OBJ/ssh_config.orig
egrep -v '^	+(Port|User)	+.*$' $OBJ/ssh_config.orig > $OBJ/ssh_config

start_sshd

verbose "$tid: no trailing slash"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@somehost:${PORT}" true
if [ $? -ne 0 ]; then
	fail "ssh connection failed"
fi

verbose "$tid: trailing slash"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@somehost:${PORT}/" true
if [ $? -ne 0 ]; then
	fail "ssh connection failed"
fi

verbose "$tid: IPv6 address"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[::1]:${PORT}/" true
if [ $? -ne 0 ]; then
	fail "ssh connection failed"
fi

verbose "$tid: IPv6 address 2"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[::a:a:a:a:a:a]:${PORT}/" true
if [ $? -ne 0 ]; then
	fail "ssh connection failed"
fi

verbose "$tid: IPv6 address "
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[::a:a:a:a:a:a]:${PORT}/" true
if [ $? -ne 0 ]; then
	fail "ssh connection failed"
fi

verbose "$tid: IPv6 address with good zone ID"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[::1%25abc]:${PORT}/" true
if [ $? -ne 0 ]; then
	fail "ssh connection failed"
fi

verbose "$tid: IPv6 address with good encoded zone ID"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[::1%25ab%25]:${PORT}/" true
if [ $? -ne 0 ]; then
	fail "ssh connection failed"
fi

verbose "$tid: IPv6 address bad zone ID"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[::1%2]:${PORT}/" true \
    > /dev/null 2>&1
if [ $? -eq 0 ]; then
	fail "ssh connection succeeded, expected failure"
fi

verbose "$tid: IPv6 address bad zone ID: non-unreserved character"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[::1%25/]:${PORT}/" true \
    > /dev/null 2>&1
if [ $? -eq 0 ]; then
	fail "ssh connection succeeded, expected failure"
fi

verbose "$tid: IPv6 address bad zone ID: bad % encoding"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[::1%25a%2]:${PORT}/" true \
    > /dev/null 2>&1
if [ $? -eq 0 ]; then
	fail "ssh connection succeeded, expected failure"
fi

verbose "$tid: IPv6 address bad zone ID: NUL byte"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[::1%25a%00]:${PORT}/" true \
    > /dev/null 2>&1
if [ $? -eq 0 ]; then
	fail "ssh connection succeeded, expected failure"
fi

verbose "$tid: IPv6 address too many hex digits"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[::aaaaa]:${PORT}/" true \
    > /dev/null 2>&1
if [ $? -eq 0 ]; then
	fail "ssh connection succeeded, expected failure"
fi

verbose "$tid: IPv6 address single leading colon"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[:0:0:0:0:0:0:0]:${PORT}/" true \
    > /dev/null 2>&1
if [ $? -eq 0 ]; then
	fail "ssh connection succeeded, expected failure"
fi

verbose "$tid: IPv6 address single trailing colon"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[0:0:0:0:0:0:0:]:${PORT}/" true \
    > /dev/null 2>&1
if [ $? -eq 0 ]; then
	fail "ssh connection succeeded, expected failure"
fi

verbose "$tid: IPv6 address too many components"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[0:0:0:0:0:0:0:0:0]:${PORT}/" true \
    > /dev/null 2>&1
if [ $? -eq 0 ]; then
	fail "ssh connection succeeded, expected failure"
fi

verbose "$tid: IPv6 address leading and trailing double colon"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@[::0::]:${PORT}/" true \
    > /dev/null 2>&1
if [ $? -eq 0 ]; then
	fail "ssh connection succeeded, expected failure"
fi

verbose "$tid: with path name"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@somehost:${PORT}/${DATA}" true \
    > /dev/null 2>&1
if [ $? -eq 0 ]; then
	fail "ssh connection succeeded, expected failure"
fi
