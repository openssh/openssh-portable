/* 	$OpenBSD: tests.c,v 1.2 2020/05/29 01:21:35 dtucker Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "test_helper.h"

#include "misc.h"

void
tests(void)
{
	int port;
	char *user, *host, *path;

	TEST_START("misc_parse_user_host_path");
	ASSERT_INT_EQ(parse_user_host_path("someuser@some.host:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(path, "some/path");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv4_path");
	ASSERT_INT_EQ(parse_user_host_path("someuser@1.22.33.144:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_path");
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_nopath");
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, ".");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv6_path");
	ASSERT_INT_EQ(parse_user_host_path("someuser@[::1]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_STRING_EQ(path, "some/path");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_uri");
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://someuser@some.host:22/some/path",
	    &user, &host, &port, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(port, 22);
	ASSERT_STRING_EQ(path, "some/path");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_convtime");
	ASSERT_LONG_EQ(convtime("1"), 1);
	ASSERT_LONG_EQ(convtime("2s"), 2);
	ASSERT_LONG_EQ(convtime("3m"), 180);
	ASSERT_LONG_EQ(convtime("1m30"), 90);
	ASSERT_LONG_EQ(convtime("1m30s"), 90);
	ASSERT_LONG_EQ(convtime("1h1s"), 3601);
	ASSERT_LONG_EQ(convtime("1h30m"), 90 * 60);
	ASSERT_LONG_EQ(convtime("1d"), 24 * 60 * 60);
	ASSERT_LONG_EQ(convtime("1w"), 7 * 24 * 60 * 60);
	ASSERT_LONG_EQ(convtime("1w2d3h4m5"), 788645);
	ASSERT_LONG_EQ(convtime("1w2d3h4m5s"), 788645);
	/* any negative number or error returns -1 */
	ASSERT_LONG_EQ(convtime("-1"),  -1);
	ASSERT_LONG_EQ(convtime(""),  -1);
	ASSERT_LONG_EQ(convtime("trout"),  -1);
	ASSERT_LONG_EQ(convtime("-77"),  -1);
	TEST_DONE();
}
