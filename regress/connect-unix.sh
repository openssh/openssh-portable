tid="simple connect"

SCRIPT_DIR=`dirname $0`

start_sshd_unix()
{
	${SUDO} env NC=${NC} SSHD=${SSHD} OBJ=${OBJ} ${SCRIPT_DIR}/sshd-unix.sh

	trace "wait for sshd-unix"
	i=0;
	while [ ! -f ${OBJ}/sshd-unix.pid -a $i -lt 10 ]; do
		i=`expr $i + 1`
		sleep $i
	done

	i=0;
	while [ ! -S ${OBJ}/sshd.socket -a $i -lt 10 ]; do
		i=`expr $i + 1`
		sleep $i
	done

	test -S ${OBJ}/sshd.socket || fatal "no sshd.socket created"
	${SUDO} chmod 0666 ${OBJ}/sshd.socket
	ls -l ${OBJ}/sshd.socket
}

stop_sshd_unix()
{
	kill `cat ${OBJ}/sshd-unix.pid`
}


# create client config
sed -e /Hostname/d -e /HostKeyAlias/d -e /Port/d -e /StrictHostKeyChecking/d < $OBJ/ssh_config > $OBJ/ssh_unix_config
echo StrictHostKeyChecking=no >> $OBJ/ssh_unix_config

start_sshd_unix

trace "direct unix socket connect"
ls -l ${OBJ}/sshd.socket
${SSH} -F ${OBJ}/ssh_unix_config ${OBJ}/sshd.socket true
if [ $? -ne 0 ]; then
	fail "ssh direct connect unix failed"
fi

