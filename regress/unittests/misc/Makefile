#	$OpenBSD: Makefile,v 1.2 2019/08/22 21:47:27 bluhm Exp $

PROG=test_misc
SRCS=tests.c

# From usr.bin/ssh/Makefile.inc
SRCS+=	sshbuf.c
SRCS+=	sshbuf-getput-basic.c
SRCS+=	sshbuf-misc.c
SRCS+=	ssherr.c
SRCS+=	log.c
SRCS+=	xmalloc.c
SRCS+=	misc.c

# From usr.bin/ssh/sshd/Makefile
SRCS+=	atomicio.c cleanup.c fatal.c

REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG}

.include <bsd.regress.mk>
