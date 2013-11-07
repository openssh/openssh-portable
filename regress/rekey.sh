#	$OpenBSD: rekey.sh,v 1.11 2013/11/07 01:12:51 dtucker Exp $
#	Placed in the Public Domain.

tid="rekey"

LOG=${TEST_SSH_LOGFILE}

rm -f ${LOG}

# Test rekeying based on data volume only.
# Arguments will be passed to ssh.
ssh_data_rekeying()
{
	rm -f ${COPY} ${LOG}
	${SSH} <${DATA} -oCompression=no $@ -v -F $OBJ/ssh_proxy somehost \
		"cat > ${COPY}"
	if [ $? -ne 0 ]; then
		fail "ssh failed ($@)"
	fi
	cmp ${DATA} ${COPY}		|| fail "corrupted copy ($@)"
	n=`grep 'NEWKEYS sent' ${LOG} | wc -l`
	n=`expr $n - 1`
	trace "$n rekeying(s)"
	if [ $n -lt 1 ]; then
		fail "no rekeying occured ($@)"
	fi
}

opts=""
for i in `${SSH} -Q kex`; do
	opts="$opts KexAlgorithms=$i"
done
for i in `${SSH} -Q cipher`; do
	opts="$opts Ciphers=$i"
done
for i in `${SSH} -Q mac`; do
	opts="$opts MACs=$i"
done

for opt in $opts; do
	verbose "client rekey $opt"
	ssh_data_rekeying -oRekeyLimit=16 -o$opt
done

# GCM is magical so test with all KexAlgorithms
if ${SSH} -Q cipher | grep gcm@openssh.com >/dev/null ; then
  for c in `${SSH} -Q cipher | grep gcm@openssh.com`; do
    for kex in `${SSH} -Q kex`; do
	verbose "client rekey $c $kex"
	ssh_data_rekeying -oRekeyLimit=16 -oCiphers=$c -oKexAlgorithms=$kex
    done
  done
fi

for s in 16 1k 128k 256k; do
	verbose "client rekeylimit ${s}"
	ssh_data_rekeying -oCompression=no -oRekeyLimit=$s
done

for s in 5 10; do
	verbose "client rekeylimit default ${s}"
	rm -f ${COPY} ${LOG}
	${SSH} < ${DATA} -oCompression=no -oRekeyLimit="default $s" -F \
		$OBJ/ssh_proxy somehost "cat >${COPY};sleep $s;sleep 3"
	if [ $? -ne 0 ]; then
		fail "ssh failed"
	fi
	cmp ${DATA} ${COPY}		|| fail "corrupted copy"
	n=`grep 'NEWKEYS sent' ${LOG} | wc -l`
	n=`expr $n - 1`
	trace "$n rekeying(s)"
	if [ $n -lt 1 ]; then
		fail "no rekeying occured"
	fi
done

for s in 5 10; do
	verbose "client rekeylimit default ${s} no data"
	rm -f ${COPY} ${LOG}
	${SSH} -oCompression=no -oRekeyLimit="default $s" -F \
		$OBJ/ssh_proxy somehost "sleep $s;sleep 3"
	if [ $? -ne 0 ]; then
		fail "ssh failed"
	fi
	n=`grep 'NEWKEYS sent' ${LOG} | wc -l`
	n=`expr $n - 1`
	trace "$n rekeying(s)"
	if [ $n -lt 1 ]; then
		fail "no rekeying occured"
	fi
done

echo "rekeylimit default 5" >>$OBJ/sshd_proxy
for s in 5 10; do
	verbose "server rekeylimit default ${s} no data"
	rm -f ${COPY} ${LOG}
	${SSH} -oCompression=no -F $OBJ/ssh_proxy somehost "sleep $s;sleep 3"
	if [ $? -ne 0 ]; then
		fail "ssh failed"
	fi
	n=`grep 'NEWKEYS sent' ${LOG} | wc -l`
	n=`expr $n - 1`
	trace "$n rekeying(s)"
	if [ $n -lt 1 ]; then
		fail "no rekeying occured"
	fi
done

verbose "rekeylimit parsing"
for size in 16 1k 1K 1m 1M 1g 1G; do
    for time in 1 1m 1M 1h 1H 1d 1D 1w 1W; do
	case $size in
		16)	bytes=16 ;;
		1k|1K)	bytes=1024 ;;
		1m|1M)	bytes=1048576 ;;
		1g|1G)	bytes=1073741824 ;;
	esac
	case $time in
		1)	seconds=1 ;;
		1m|1M)	seconds=60 ;;
		1h|1H)	seconds=3600 ;;
		1d|1D)	seconds=86400 ;;
		1w|1W)	seconds=604800 ;;
	esac

	b=`$SUDO ${SSHD} -T -o "rekeylimit $size $time" -f $OBJ/sshd_proxy | \
	    awk '/rekeylimit/{print $2}'`
	s=`$SUDO ${SSHD} -T -o "rekeylimit $size $time" -f $OBJ/sshd_proxy | \
	    awk '/rekeylimit/{print $3}'`

	if [ "$bytes" != "$b" ]; then
		fatal "rekeylimit size: expected $bytes got $b"
	fi
	if [ "$seconds" != "$s" ]; then
		fatal "rekeylimit time: expected $time got $s"
	fi
    done
done

rm -f ${COPY} ${DATA}
