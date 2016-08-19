#	$OpenBSD: Makefile,v 1.1 2016/08/19 06:44:13 djm Exp $

TEST_ENV=      "MALLOC_OPTIONS=AFGJPRX"

PROG=test_match
SRCS=tests.c
REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG}

.include <bsd.regress.mk>
