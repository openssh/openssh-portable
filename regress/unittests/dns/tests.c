/* 	$OpenBSD: tests.c,v 1.3 2021/01/18 11:43:34 dtucker Exp $ */
/*
 * Regress test for dns utility functions
 *
 * Placed in the public domain
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "../test_helper/test_helper.h"

#include "sshkey.h"
#include "dns.h"

void
tests(void)
{
    TEST_START("dns_decode_name");

    // no data at all
	ASSERT_PTR_EQ(dns_decode_name(0, 0), NULL);

    // some data, but truncated a lot
	ASSERT_PTR_EQ(dns_decode_name("\04example", 4), NULL);

    // some data, but truncated (trailing zero length label missing)
	ASSERT_PTR_EQ(dns_decode_name("\07example", 8), NULL);

    // single label, correct data
	ASSERT_STRING_EQ(dns_decode_name("\07example", 9), "example");

    // two labels, correct data
	ASSERT_STRING_EQ(dns_decode_name("\07example\03com", 13), "example.com");

    // three labels, correct data
	ASSERT_STRING_EQ(dns_decode_name("\03www\07example\03com", 17), "www.example.com");

	TEST_DONE();
}
