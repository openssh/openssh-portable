#	$OpenBSD: connect.sh,v 1.7 2020/01/24 10:08:17 dtucker Exp $
#	Placed in the Public Domain.

tid="simple connect"

NC=nc

start_sshd

trace "direct connect"
${SSH} -F $OBJ/ssh_config somehost true
if [ $? -ne 0 ]; then
	fail "ssh direct connect failed"
fi

trace "proxy connect"
${SSH} -F $OBJ/ssh_config -o "proxycommand $NC %h %p" somehost true
if [ $? -ne 0 ]; then
	fail "ssh proxycommand connect failed"
fi
