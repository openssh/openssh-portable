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

verbose "$tid: with path name"
${SSH} -F $OBJ/ssh_config "ssh://${USER}@somehost:${PORT}/${DATA}" true \
    > /dev/null 2>&1
if [ $? -eq 0 ]; then
	fail "ssh connection succeeded, expected failure"
fi

check_v6_pass () {
	_tag="$1"
	_url="$2"
	verbose "$tid: Valid IPv6 URL $_tag"
	${SSH} -F $OBJ/ssh_config "$_url" true >/dev/null ||
		fail "IPv6 URL connection failed: $_tag: $_url"
}

check_v6_fail () {
	_tag="$1"
	_url="$2"
	verbose "$tid: Invalid IPv6 URL $_tag"
	if ${SSH} -F $OBJ/ssh_config "$_url" true >/dev/null 2>&1; then
		fail "IPv6 URL connection succeeded: $_tag: $_url"
	fi
}

check_v6_pass loopback "ssh://${USER}@[::1]:${PORT}/"
check_v6_pass 'leading double colon' "ssh://${USER}@[::a:a:a:a:a:a]:${PORT}/"
check_v6_pass 'trailing double colon' "ssh://${USER}@[a:a:a:a:a:a::]:${PORT}/"
check_v6_pass 'no double colon' "ssh://${USER}@[a:a:a:a:a:a:a:a]:${PORT}/"
check_v6_pass 'good zone ID' "ssh://${USER}@[fe80::1%25lo5]:${PORT}/"
check_v6_pass 'good encoded zone ID' "ssh://${USER}@[fe80::1%25l%6f]:${PORT}/"
check_v6_fail 'bad zone ID: % not %-encoded' "ssh://${USER}@[::1%2]:${PORT}/"
check_v6_fail 'bad zone ID: non-unreserved character' "ssh://${USER}@[::1%25/]:${PORT}/"
check_v6_fail 'bad zone ID: bad % encoding' "ssh://${USER}@[::1%25a%2]:${PORT}/"
check_v6_fail 'bad zone ID: NUL byte' "ssh://${USER}@[::1%25a%00]:${PORT}/"
check_v6_fail 'too many hex digits' "ssh://${USER}@[::aaaaa]:${PORT}/"
check_v6_fail 'single leading colon' "ssh://${USER}@[:0:0:0:0:0:0:0]:${PORT}/"
check_v6_fail 'single trailing colon' "ssh://${USER}@[0:0:0:0:0:0:0:]:${PORT}/"
check_v6_fail 'too many components' "ssh://${USER}@[0:0:0:0:0:0:0:0:0]:${PORT}/"
check_v6_fail 'leading and trailing double colon' "ssh://${USER}@[::0::]:${PORT}/"
