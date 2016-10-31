#	$OpenBSD: Makefile,v 1.3 2016/10/31 23:45:09 tb Exp $

TEST_ENV=      "MALLOC_OPTIONS=FGJRX"

PROG=test_kex
SRCS=tests.c test_kex.c
REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG}

.include <bsd.regress.mk>

LDADD+=-lz
