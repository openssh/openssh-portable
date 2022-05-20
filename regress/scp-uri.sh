#	$OpenBSD: scp-uri.sh,v 1.4 2021/08/10 03:35:45 djm Exp $
#	Placed in the Public Domain.

tid="scp-uri"

#set -x

COPY2=${OBJ}/copy2
DIR=${COPY}.dd
DIR2=${COPY}.dd2

SRC=`dirname ${SCRIPT}`
cp ${SRC}/scp-ssh-wrapper.sh ${OBJ}/scp-ssh-wrapper.scp
chmod 755 ${OBJ}/scp-ssh-wrapper.scp
export SCP # used in scp-ssh-wrapper.scp

scpclean() {
	rm -rf ${COPY} ${COPY2} ${DIR} ${DIR2}
	mkdir ${DIR} ${DIR2}
}

# Remove Port and User from ssh_config, we want to rely on the URI
cp $OBJ/ssh_config $OBJ/ssh_config.orig
egrep -v '^	+(Port|User)	+.*$' $OBJ/ssh_config.orig > $OBJ/ssh_config

for mode in scp sftp ; do
	tag="$tid: $mode mode"
	if test $mode = scp ; then
		scpopts="-O -q -S ${OBJ}/scp-ssh-wrapper.scp"
	else
		scpopts="-s -D ${SFTPSERVER}"
	fi
	verbose "$tag: simple copy local file to remote file"
	scpclean
	$SCP $scpopts ${DATA} "scp://${USER}@somehost:${PORT}/${COPY}" || fail "copy failed"
	cmp ${DATA} ${COPY} || fail "corrupted copy"

	verbose "$tag: simple copy remote file to local file"
	scpclean
	$SCP $scpopts "scp://${USER}@somehost:${PORT}/${DATA}" ${COPY} || fail "copy failed"
	cmp ${DATA} ${COPY} || fail "corrupted copy"

	verbose "$tag: simple copy local file to remote dir"
	scpclean
	cp ${DATA} ${COPY}
	$SCP $scpopts ${COPY} "scp://${USER}@somehost:${PORT}/${DIR}" || fail "copy failed"
	cmp ${COPY} ${DIR}/copy || fail "corrupted copy"

	verbose "$tag: simple copy remote file to local dir"
	scpclean
	cp ${DATA} ${COPY}
	$SCP $scpopts "scp://${USER}@somehost:${PORT}/${COPY}" ${DIR} || fail "copy failed"
	cmp ${COPY} ${DIR}/copy || fail "corrupted copy"

	verbose "$tag: recursive local dir to remote dir"
	scpclean
	rm -rf ${DIR2}
	cp ${DATA} ${DIR}/copy
	$SCP $scpopts -r ${DIR} "scp://${USER}@somehost:${PORT}/${DIR2}" || fail "copy failed"
	for i in $(cd ${DIR} && echo *); do
		cmp ${DIR}/$i ${DIR2}/$i || fail "corrupted copy"
	done

	verbose "$tag: recursive remote dir to local dir"
	scpclean
	rm -rf ${DIR2}
	cp ${DATA} ${DIR}/copy
	$SCP $scpopts -r "scp://${USER}@somehost:${PORT}/${DIR}" ${DIR2} || fail "copy failed"
	for i in $(cd ${DIR} && echo *); do
		cmp ${DIR}/$i ${DIR2}/$i || fail "corrupted copy"
	done
done

# tests file being smaller (copy)
# a file being larger (copy2)
# and a file that should be skipped (copy3)
verbose "$tid: resume function from remote to local"
scpclean
rm -rf ${DIR2}
cp ${DATA} ${DIR}/copy
cp ${DATA} ${DIR}/copy2
cp ${DATA} ${DIR}/copy3
$SCP $scpopts -r "scp://${USER}@somehost:${PORT}/${DIR}" ${DIR2} || fail "copy failed"
truncate --size=-512 ${DIR2}/copy
truncate --size=+512 ${DIR2}/copy2
$SCP $scpopts -R -s $SCP "scp://${USER}@somehost:${PORT}/${DIR}/copy*" ${DIR2} || fail "resume failed"
for i in $(cd ${DIR} && echo *); do
        cmp ${DIR}/$i ${DIR2}/$i || fail "corrupted resume copy"
done

verbose "$tid: resume function from local to remote"
scpclean
rm -rf ${DIR2}
cp ${DATA} ${DIR}/copy
cp ${DATA} ${DIR}/copy2
cp ${DATA} ${DIR}/copy3
$SCP $scpopts -r ${DIR} "scp://${USER}@somehost:${PORT}/${DIR2}" || fail "copy failed"
truncate --size=-512 ${DIR2}/copy
truncate --size=+512 ${DIR2}/copy2
$SCP $scpopts -R -s $SCP ${DIR}/copy* "scp://${USER}@somehost:${PORT}/${DIR2}" || fail "resume failed"
for i in $(cd ${DIR} && echo *); do
        cmp ${DIR}/$i ${DIR2}/$i || fail "corrupted resume copy"
done

scpclean
rm -f ${OBJ}/scp-ssh-wrapper.exe
