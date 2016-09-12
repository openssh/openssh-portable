#	$OpenBSD: keygen-moduli.sh,v 1.1 2016/09/12 02:25:46 dtucker Exp $
#	Placed in the Public Domain.

tid="keygen moduli"

for i in 0 1 2; do
	rm -f $OBJ/moduli.out $OBJ/moduli.ckpt
	${SSHKEYGEN} -T $OBJ/moduli.out -f ${SRC}/moduli.in -j$i -J1 \
	    -K $OBJ/moduli.ckpt 2>/dev/null || \
	    fail "keygen screen failed line $i"
	lines=`wc -l <$OBJ/moduli.out`
	test "$lines" -eq "1" || fail "expected 1 line, got $lines"
done

rm -f $OBJ/moduli.out $OBJ/moduli.ckpt
