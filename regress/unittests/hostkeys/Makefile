#	$OpenBSD: Makefile,v 1.2 2016/10/31 23:45:08 tb Exp $

TEST_ENV=      "MALLOC_OPTIONS=FGJRX"

PROG=test_hostkeys
SRCS=tests.c test_iterate.c
REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG} -d ${.CURDIR}/testdata

.include <bsd.regress.mk>
