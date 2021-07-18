#	$OpenBSD: keygen-sshfp.sh,v 1.1 2021/07/18 23:10:10 dtucker Exp $
#	Placed in the Public Domain.

tid="keygen-sshfp"

trace "keygen fingerprints"
fp=`${SSHKEYGEN} -r test -f ${SRC}/rsa_openssh.pub | awk '$5=="1"{print $6}'`
if [ "$fp" != "99c79cc09f5f81069cc017cdf9552cfc94b3b929" ]; then
	fail "keygen fingerprint sha1"
fi
fp=`${SSHKEYGEN} -r test -f ${SRC}/rsa_openssh.pub | awk '$5=="2"{print $6}'`
if [ "$fp" != \
    "e30d6b9eb7a4de495324e4d5870b8220577993ea6af417e8e4a4f1c5bf01a9b6" ]; then
	fail "keygen fingerprint sha256"
fi
