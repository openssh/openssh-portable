#!/bin/bash

# Init file for OpenSSH server daemon
#
# chkconfig: 2345 55 25
# description: OpenSSH server daemon
#
# processname: sshd
# config: /etc/ssh/ssh_host_key
# config: /etc/ssh/ssh_host_key.pub
# config: /etc/ssh/ssh_random_seed
# config: /etc/ssh/sshd_config
# pidfile: /var/run/sshd.pid

# source function library
. /etc/rc.d/init.d/functions

RETVAL=0

case "$1" in
	start)
		echo -n "Starting sshd: "
		if [ ! -f /var/run/sshd.pid ] ; then
			case "`type -type success`" in
				function)
					/usr/sbin/sshd && success "sshd startup" || failure "sshd startup"
					RETVAL=$?
					;;
				*)
					/usr/sbin/sshd && echo -n "sshd "
					RETVAL=$?
					;;
			esac
			[ $RETVAL -eq 0 ] && touch /var/lock/subsys/sshd
		fi
		echo
		;;
	stop)
		echo -n "Shutting down sshd: "
		if [ -f /var/run/sshd.pid ] ; then
			killproc sshd
		fi
		echo
		[ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/sshd
		;;
	restart)
		$0 stop
		$0 start
		RETVAL=$?
		;;
	status)
		status sshd
		RETVAL=$?
		;;
	*)
		echo "Usage: sshd {start|stop|restart|status}"
		exit 1
		;;
esac

exit $RETVAL
