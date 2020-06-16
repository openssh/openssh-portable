#	$OpenBSD: Makefile,v 1.1 2019/04/28 22:53:26 dtucker Exp $

PROG=test_misc
SRCS=tests.c

# From usr.bin/ssh/Makefile.inc
SRCS+=sshbuf.c sshbuf-getput-basic.c ssherr.c log.c xmalloc.c misc.c
# From usr/bin/ssh/sshd/Makefile
SRCS+=atomicio.c cleanup.c fatal.c

REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG}

.include <bsd.regress.mk>
