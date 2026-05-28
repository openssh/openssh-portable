/*
 * Regression test for scan_scaled() fractional-part scaling.
 *
 * Before the fix to openbsd-compat/fmt_scaled.c, scan_scaled() truncated
 * the fractional part of inputs with large units (E and sometimes P) all
 * the way to zero, because the overflow guard divided fpart by 10 until
 * fpart * scale_fact fit in long long -- without accounting for the
 * later divide-by-10^(fract_digits-1).  As a result, e.g. "0.9E" parsed
 * to 0 (100% error) and "1.9E" parsed to 1E (~47% error).
 */

#include "includes.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

/* LLONG_MAX/MIN aliases on AIX/HP-UX (matches strtonumtest.c). */
#if defined(LONGLONG_MAX) && !defined(LLONG_MAX)
# define LLONG_MAX LONGLONG_MAX
# define LLONG_MIN LONGLONG_MIN
#endif
#if defined(LONG_LONG_MAX) && !defined(LLONG_MAX)
# define LLONG_MAX LONG_LONG_MAX
# define LLONG_MIN LONG_LONG_MIN
#endif

int scan_scaled(char *, long long *);

static int failed = 0;

/*
 * Tolerance for fractional results: the interleaved mul/div algorithm
 * loses at most ~1 unit per divide-by-10 step, so the cumulative error
 * for the largest unit (E with up to ~19 fractional digits) is bounded
 * by a few thousand.  The pre-fix bug produced errors on the order of
 * 10^17 -- many orders of magnitude larger.
 */
#define TOLERANCE 4096LL

static void
check(const char *input, long long expected, int expect_ok)
{
	char buf[64];
	long long got = 0;
	int r;
	long long diff;

	strncpy(buf, input, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	errno = 0;
	r = scan_scaled(buf, &got);

	if (!expect_ok) {
		if (r == 0) {
			fprintf(stderr, "scan_scaledtest: %s "
			    "expected ERANGE/EINVAL, got %lld\n",
			    input, got);
			failed = 1;
		}
		return;
	}
	if (r != 0) {
		fprintf(stderr, "scan_scaledtest: %s "
		    "expected %lld, got error: %s\n",
		    input, expected, strerror(errno));
		failed = 1;
		return;
	}
	diff = got - expected;
	if (diff < 0)
		diff = -diff;
	if (diff > TOLERANCE) {
		fprintf(stderr, "scan_scaledtest: %s "
		    "expected ~%lld, got %lld (diff %lld)\n",
		    input, expected, got, diff);
		failed = 1;
	}
}

int
main(void)
{
	const long long K = 1024LL;
	const long long M = K * K;
	const long long G = M * K;
	const long long T = G * K;
	const long long P = T * K;
	const long long E = P * K;

	/* Whole-number sanity. */
	check("0", 0, 1);
	check("100", 100, 1);
	check("1K", K, 1);
	check("1M", M, 1);
	check("1G", G, 1);
	check("1T", T, 1);
	check("1P", P, 1);
	check("1E", E, 1);
	check("-1E", -E, 1);
	check("7E", 7 * E, 1);

	/* Fractional cases that worked before. */
	check("1.5K", K + K / 2, 1);
	check("2.5M", 2 * M + M / 2, 1);
	check("1.5G", G + G / 2, 1);
	check("0.5E", E / 2, 1);
	check("1.5E", E + E / 2, 1);

	/*
	 * The pre-fix bug cases.  Before the fix, these all returned
	 * values off by ~10^17 (e.g. "0.9E" returned 0; "1.9E" returned
	 * exactly 1 * E).  After the fix they're within rounding noise.
	 */
	check("0.9E", (9 * E) / 10, 1);
	check("0.1E", E / 10, 1);
	check("1.9E", E + (9 * E) / 10, 1);
	check("-1.9E", -(E + (9 * E) / 10), 1);
	check("3.7E", 3 * E + (7 * E) / 10, 1);
	check("7.9E", 7 * E + (9 * E) / 10, 1);
	check("1.234567T", T + (T * 234567LL) / 1000000LL, 1);
	check("0.0001P", P / 10000, 1);

	/* Out-of-range. */
	check("9223372036854775808", 0, 0);	/* > LLONG_MAX */
	check("9E", 0, 0);			/* 9 * 2^60 > LLONG_MAX */
	check("garbage", 0, 0);
	check("1Z", 0, 0);			/* unknown unit */

	return failed;
}
