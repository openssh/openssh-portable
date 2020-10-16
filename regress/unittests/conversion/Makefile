#	$OpenBSD: Makefile,v 1.3 2020/10/16 14:02:24 djm Exp $

PROG=test_conversion
SRCS=tests.c

# From usr.bin/ssh
SRCS+=sshbuf-getput-basic.c sshbuf-getput-crypto.c sshbuf-misc.c sshbuf.c
SRCS+=atomicio.c misc.c xmalloc.c log.c uidswap.c cleanup.c fatal.c ssherr.c
SRCS+=match.c addrmatch.c

REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG}

.include <bsd.regress.mk>
