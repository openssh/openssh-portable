#	$OpenBSD: hostkey-agent.sh,v 1.1 2015/01/17 18:54:30 djm Exp $
#	Placed in the Public Domain.

tid="hostkey agent"

# Need full names here since they are used in HostKeyAlgorithms
HOSTKEY_TYPES="ecdsa-sha2-nistp256 ssh-ed25519 ssh-rsa ssh-dss"

rm -f $OBJ/agent.* $OBJ/ssh_proxy.orig

trace "start agent"
eval `${SSHAGENT} -s` > /dev/null
r=$?
[ $r -ne 0 ] && fatal "could not start ssh-agent: exit code $r"

grep -vi 'hostkey' $OBJ/sshd_proxy > $OBJ/sshd_proxy.orig
echo "HostKeyAgent $SSH_AUTH_SOCK" >> $OBJ/sshd_proxy.orig
echo "LogLevel debug3" >> $OBJ/sshd_proxy.orig
rm $OBJ/known_hosts

trace "load hostkeys"
for k in $HOSTKEY_TYPES ; do
	${SSHKEYGEN} -qt $k -f $OBJ/agent.$k -N '' || fatal "ssh-keygen $k"
	(
		echo -n 'localhost-with-alias,127.0.0.1,::1 '
		cat $OBJ/agent.$k.pub
	) >> $OBJ/known_hosts
	${SSHADD} $OBJ/agent.$k >/dev/null 2>&1 || \
		fatal "couldn't load key $OBJ/agent.$k"
	echo "Hostkey $OBJ/agent.${k}" >> sshd_proxy.orig
	# Remove private key so the server can't use it.
	rm $OBJ/agent.$k || fatal "couldn't rm $OBJ/agent.$k"
done

unset SSH_AUTH_SOCK

for ps in no yes; do
	cp $OBJ/sshd_proxy.orig $OBJ/sshd_proxy
	echo "UsePrivilegeSeparation $ps" >> $OBJ/sshd_proxy
	for k in $HOSTKEY_TYPES ; do
		verbose "key type $k privsep=$ps"
		opts="-oHostKeyAlgorithms=$k -F $OBJ/ssh_proxy"
		SSH_CONNECTION=`${SSH} $opts host 'echo $SSH_CONNECTION'`
		if [ $? -ne 0 ]; then
			fail "protocol $p privsep=$ps failed"
		fi
		if [ "$SSH_CONNECTION" != "UNKNOWN 65535 UNKNOWN 65535" ]; then
			fail "bad SSH_CONNECTION key type $k privsep=$ps"
		fi
	done
done

trace "kill agent"
${SSHAGENT} -k > /dev/null

