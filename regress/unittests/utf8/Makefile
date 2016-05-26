#	$OpenBSD: Makefile,v 1.1 2016/05/26 19:14:25 schwarze Exp $

TEST_ENV=	"MALLOC_OPTIONS=AFGJPRX"

PROG=test_utf8
SRCS=tests.c
REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG}

.include <bsd.regress.mk>
