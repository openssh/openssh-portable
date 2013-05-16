#	$OpenBSD: rekey.sh,v 1.5 2013/05/16 03:33:30 dtucker Exp $
#	Placed in the Public Domain.

tid="rekey during transfer data"

DATA=${OBJ}/data
COPY=${OBJ}/copy
LOG=${TEST_SSH_LOGFILE}

rm -f ${COPY} ${LOG} ${DATA}
touch ${DATA}
dd if=/bin/ls${EXEEXT} of=${DATA} bs=1k seek=511 count=1 > /dev/null 2>&1

for s in 16 1k 128k 256k; do
	verbose "rekeylimit ${s}"
	rm -f ${COPY} ${LOG}
	cat $DATA | \
		${SSH} -oCompression=no -oRekeyLimit=$s \
			-v -F $OBJ/ssh_proxy somehost "cat > ${COPY}"
	if [ $? -ne 0 ]; then
		fail "ssh failed"
	fi
	cmp $DATA ${COPY}		|| fail "corrupted copy"
	n=`grep 'NEWKEYS sent' ${LOG} | wc -l`
	n=`expr $n - 1`
	trace "$n rekeying(s)"
	if [ $n -lt 1 ]; then
		fail "no rekeying occured"
	fi
done

for s in 5 10; do
	verbose "rekeylimit default ${s}"
	rm -f ${COPY} ${LOG}
	cat $DATA | \
		${SSH} -oCompression=no -oRekeyLimit="default $s" -F \
			$OBJ/ssh_proxy somehost "cat >${COPY};sleep $s;sleep 3"
	if [ $? -ne 0 ]; then
		fail "ssh failed"
	fi
	cmp $DATA ${COPY}		|| fail "corrupted copy"
	n=`grep 'NEWKEYS sent' ${LOG} | wc -l`
	n=`expr $n - 1`
	trace "$n rekeying(s)"
	if [ $n -lt 1 ]; then
		fail "no rekeying occured"
	fi
done

for s in 5 10; do
	verbose "rekeylimit default ${s} no data"
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

rm -f ${COPY} ${DATA}
