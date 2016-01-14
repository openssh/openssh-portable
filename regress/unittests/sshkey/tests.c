/* 	$OpenBSD: tests.c,v 1.1 2014/06/24 01:14:18 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#include "includes.h"

#ifdef USING_WOLFSSL
#include <wolfssl/openssl/evp.h>
#else
#include <openssl/evp.h>
#endif

#include "../test_helper/test_helper.h"

void sshkey_tests(void);
void sshkey_file_tests(void);
void sshkey_fuzz_tests(void);

void
tests(void)
{
	OpenSSL_add_all_algorithms();
#ifndef USING_WOLFSSL
	ERR_load_CRYPTO_strings();
#endif
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}
