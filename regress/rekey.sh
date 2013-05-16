#	$OpenBSD: rekey.sh,v 1.2 2013/04/06 06:00:22 dtucker Exp $
#	Placed in the Public Domain.

tid="rekey during transfer data"

DATA=${OBJ}/data
COPY=${OBJ}/copy
LOG=${TEST_SSH_LOGFILE}

rm -f ${COPY} ${LOG} ${DATA}
touch ${DATA}
dd if=/bin/ls${EXEEXT} of=${DATA} bs=1k seek=511 count=1 > /dev/null 2>&1

for s in 16 1k 128k 256k; do
	trace "rekeylimit ${s}"
	rm -f ${COPY}
	cat $DATA | \
		${SSH} -oCompression=no -oRekeyLimit=$s \
			-v -F $OBJ/ssh_proxy somehost "cat > ${COPY}" \
		2> ${LOG}
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
rm -f ${COPY} ${DATA}
