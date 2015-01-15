#	$OpenBSD: Makefile,v 1.1 2015/01/15 23:41:29 markus Exp $

TEST_ENV=      "MALLOC_OPTIONS=AFGJPRX"

PROG=test_kex
SRCS=tests.c test_kex.c
LDADD=-lz
REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG}

.include <bsd.regress.mk>
