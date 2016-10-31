#	$OpenBSD: Makefile,v 1.3 2016/10/31 23:45:09 tb Exp $

TEST_ENV=      "MALLOC_OPTIONS=FGJRX"

PROG=test_sshkey
SRCS=tests.c test_sshkey.c test_file.c test_fuzz.c common.c
REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG} -d ${.CURDIR}/testdata

.include <bsd.regress.mk>

