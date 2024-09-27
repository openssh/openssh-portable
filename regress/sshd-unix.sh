#!/bin/sh

# create an ssh server listening on a Unix socket, using netcat

run_sshd_unix() {
	# see example in netcat man page, modified here for a unix socket
	rm -f ${OBJ}/sshd.fifo && mkfifo ${OBJ}/sshd.fifo
	rm -f ${OBJ}/sshd.socket
	touch ${OBJ}/sshd-unix.log ; chmod 0644 ${OBJ}/sshd-unix.log
	(cat ${OBJ}/sshd.fifo | ${SSHD} -i -f ${OBJ}/sshd_config "$@" -E ${OBJ}/sshd-unix.log | ${NC} -l -U ${OBJ}/sshd.socket > ${OBJ}/sshd.fifo) &
}

run_sshd_unix
