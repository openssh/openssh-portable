#	$OpenBSD: Makefile,v 1.3 2016/10/31 23:45:09 tb Exp $

TEST_ENV=	"MALLOC_OPTIONS=CFGJRSUX"

PROG=test_utf8
SRCS=tests.c
REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG}

.include <bsd.regress.mk>
