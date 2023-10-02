/* 	$OpenBSD: test_sshbuf_getput_crypto.c,v 1.3 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include "../test_helper/test_helper.h"
#include "ssherr.h"
#include "sshbuf.h"

void sshbuf_getput_crypto_tests(void);

void
sshbuf_getput_crypto_tests(void)
{
	struct sshbuf *p1;
	BIGNUM *bn, *bn2;
	const char *hexbn1 = "0102030405060708090a0b0c0d0e0f10";
	/* This one has MSB set to test bignum2 encoding negative-avoidance */
	const char *hexbn2 = "f0e0d0c0b0a0908070605040302010007fff11";
	u_char expbn1[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	u_char expbn2[] = {
		0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80,
		0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
		0x7f, 0xff, 0x11
	};
#if defined(OPENSSL_HAS_ECC) && defined(OPENSSL_HAS_NISTP256)
	const u_char *d;
	size_t s;
	BIGNUM *bn_x, *bn_y;
	int ec256_nid = NID_X9_62_prime256v1;
	const char *ec256_sn = "prime256v1";
	char *ec256_x = "0C828004839D0106AA59575216191357"
		        "34B451459DADB586677EF9DF55784999";
	char *ec256_y = "4D196B50F0B4E94B3C73E3A9D4CD9DF2"
	                "C8F9A35E42BDD047550F69D80EC23CD4";
	u_char expec256[] = {
		0x04,
		0x0c, 0x82, 0x80, 0x04, 0x83, 0x9d, 0x01, 0x06,
		0xaa, 0x59, 0x57, 0x52, 0x16, 0x19, 0x13, 0x57,
		0x34, 0xb4, 0x51, 0x45, 0x9d, 0xad, 0xb5, 0x86,
		0x67, 0x7e, 0xf9, 0xdf, 0x55, 0x78, 0x49, 0x99,
		0x4d, 0x19, 0x6b, 0x50, 0xf0, 0xb4, 0xe9, 0x4b,
		0x3c, 0x73, 0xe3, 0xa9, 0xd4, 0xcd, 0x9d, 0xf2,
		0xc8, 0xf9, 0xa3, 0x5e, 0x42, 0xbd, 0xd0, 0x47,
		0x55, 0x0f, 0x69, 0xd8, 0x0e, 0xc2, 0x3c, 0xd4
	};
	EVP_PKEY *eck = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *param_bld = NULL;
	OSSL_PARAM *params = NULL;
	EC_GROUP *g = NULL;
	u_char *pubkey = NULL;
	size_t pubkey_len;
	EC_POINT *ecp;
#endif
	int r;

#define MKBN(b, bnn) \
	do { \
		bnn = NULL; \
		ASSERT_INT_GT(BN_hex2bn(&bnn, b), 0); \
	} while (0)

	TEST_START("sshbuf_put_bignum2");
	MKBN(hexbn1, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, NULL);
	ASSERT_INT_EQ(sshbuf_put_bignum2(p1, bn), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), sizeof(expbn1) + 4);
	ASSERT_U32_EQ(PEEK_U32(sshbuf_ptr(p1)), (u_int32_t)BN_num_bytes(bn));
	ASSERT_MEM_EQ(sshbuf_ptr(p1) + 4, expbn1, sizeof(expbn1));
	BN_free(bn);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_put_bignum2 limited");
	MKBN(hexbn1, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, NULL);
	ASSERT_INT_EQ(sshbuf_set_max_size(p1, sizeof(expbn1) + 3), 0);
	r = sshbuf_put_bignum2(p1, bn);
	ASSERT_INT_EQ(r, SSH_ERR_NO_BUFFER_SPACE);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 0);
	BN_free(bn);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_put_bignum2 bn2");
	MKBN(hexbn2, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, NULL);
	ASSERT_INT_EQ(sshbuf_put_bignum2(p1, bn), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), sizeof(expbn2) + 4 + 1); /* MSB */
	ASSERT_U32_EQ(PEEK_U32(sshbuf_ptr(p1)), (u_int32_t)BN_num_bytes(bn) + 1);
	ASSERT_U8_EQ(*(sshbuf_ptr(p1) + 4), 0x00);
	ASSERT_MEM_EQ(sshbuf_ptr(p1) + 5, expbn2, sizeof(expbn2));
	BN_free(bn);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_put_bignum2 bn2 limited");
	MKBN(hexbn2, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, NULL);
	ASSERT_INT_EQ(sshbuf_set_max_size(p1, sizeof(expbn2) + 3), 0);
	r = sshbuf_put_bignum2(p1, bn);
	ASSERT_INT_EQ(r, SSH_ERR_NO_BUFFER_SPACE);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 0);
	BN_free(bn);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_get_bignum2");
	MKBN(hexbn1, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, NULL);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, BN_num_bytes(bn)), 0);
	ASSERT_INT_EQ(sshbuf_put(p1, expbn1, sizeof(expbn1)), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 4 + sizeof(expbn1));
	ASSERT_INT_EQ(sshbuf_put_u16(p1, 0xd00f), 0);
	bn2 = NULL;
	ASSERT_INT_EQ(sshbuf_get_bignum2(p1, &bn2), 0);
	ASSERT_BIGNUM_EQ(bn, bn2);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 2);
	BN_free(bn);
	BN_free(bn2);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_get_bignum2 truncated");
	MKBN(hexbn1, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, NULL);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, BN_num_bytes(bn)), 0);
	ASSERT_INT_EQ(sshbuf_put(p1, expbn1, sizeof(expbn1) - 1), 0);
	bn2 = NULL;
	r = sshbuf_get_bignum2(p1, &bn2);
	ASSERT_INT_EQ(r, SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), sizeof(expbn1) + 3);
	BN_free(bn);
	BN_free(bn2);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_get_bignum2 giant");
	MKBN(hexbn1, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, NULL);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 65536), 0);
	ASSERT_INT_EQ(sshbuf_reserve(p1, 65536, NULL), 0);
	bn2 = NULL;
	r = sshbuf_get_bignum2(p1, &bn2);
	ASSERT_INT_EQ(r, SSH_ERR_BIGNUM_TOO_LARGE);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 65536 + 4);
	BN_free(bn);
	BN_free(bn2);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_get_bignum2 bn2");
	MKBN(hexbn2, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, NULL);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, BN_num_bytes(bn) + 1), 0); /* MSB */
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x00), 0);
	ASSERT_INT_EQ(sshbuf_put(p1, expbn2, sizeof(expbn2)), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 4 + 1 + sizeof(expbn2));
	ASSERT_INT_EQ(sshbuf_put_u16(p1, 0xd00f), 0);
	bn2 = NULL;
	ASSERT_INT_EQ(sshbuf_get_bignum2(p1, &bn2), 0);
	ASSERT_BIGNUM_EQ(bn, bn2);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 2);
	BN_free(bn);
	BN_free(bn2);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_get_bignum2 bn2 truncated");
	MKBN(hexbn2, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, NULL);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, BN_num_bytes(bn) + 1), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x00), 0);
	ASSERT_INT_EQ(sshbuf_put(p1, expbn2, sizeof(expbn2) - 1), 0);
	bn2 = NULL;
	r = sshbuf_get_bignum2(p1, &bn2);
	ASSERT_INT_EQ(r, SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), sizeof(expbn2) + 1 + 4 - 1);
	BN_free(bn);
	BN_free(bn2);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_get_bignum2 bn2 negative");
	MKBN(hexbn2, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, NULL);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, BN_num_bytes(bn)), 0);
	ASSERT_INT_EQ(sshbuf_put(p1, expbn2, sizeof(expbn2)), 0);
	bn2 = NULL;
	r = sshbuf_get_bignum2(p1, &bn2);
	ASSERT_INT_EQ(r, SSH_ERR_BIGNUM_IS_NEGATIVE);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), sizeof(expbn2) + 4);
	BN_free(bn);
	BN_free(bn2);
	sshbuf_free(p1);
	TEST_DONE();

#if defined(OPENSSL_HAS_ECC) && defined(OPENSSL_HAS_NISTP256)
	TEST_START("sshbuf_put_ec");
	param_bld = OSSL_PARAM_BLD_new();
	ASSERT_PTR_NE(param_bld, NULL);
	ASSERT_INT_EQ(OSSL_PARAM_BLD_push_utf8_string(param_bld,
	    OSSL_PKEY_PARAM_GROUP_NAME, ec256_sn, strlen(ec256_sn)), 1);
	MKBN(ec256_x, bn_x);
	MKBN(ec256_y, bn_y);
	g = EC_GROUP_new_by_curve_name(ec256_nid);
	ecp = EC_POINT_new(g);
	ASSERT_PTR_NE(g, NULL);
	ASSERT_INT_EQ(EC_POINT_set_affine_coordinates(
	    g, ecp, bn_x, bn_y, NULL), 1);
	BN_free(bn_x);
	BN_free(bn_y);
	pubkey_len = EC_POINT_point2oct(g, ecp,
	    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	ASSERT_INT_NE(pubkey_len, 0);
	pubkey = malloc(pubkey_len);
	ASSERT_PTR_NE(pubkey, NULL);
	ASSERT_INT_NE(EC_POINT_point2oct(g, ecp, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, pubkey_len, NULL), 0);
	EC_GROUP_free(g);
	EC_POINT_free(ecp);
	ASSERT_INT_EQ(OSSL_PARAM_BLD_push_octet_string(param_bld,
	    OSSL_PKEY_PARAM_PUB_KEY, pubkey, pubkey_len), 1);
	params = OSSL_PARAM_BLD_to_param(param_bld);
	ASSERT_PTR_NE(params, NULL);
	OSSL_PARAM_BLD_free(param_bld);
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	ASSERT_PTR_NE(ctx, NULL);
	ASSERT_INT_EQ(EVP_PKEY_fromdata_init(ctx), 1);
	ASSERT_INT_EQ(EVP_PKEY_fromdata(ctx, &eck, EVP_PKEY_PUBLIC_KEY,
	    params), 1);
	free(pubkey);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, NULL);
	ASSERT_INT_EQ(sshbuf_put_ec(p1, eck), 0);
	ASSERT_INT_EQ(sshbuf_get_string_direct(p1, &d, &s), 0);
	ASSERT_SIZE_T_EQ(s, sizeof(expec256));
	ASSERT_MEM_EQ(d, expec256, sizeof(expec256));
	sshbuf_free(p1);
	EVP_PKEY_free(eck);
	TEST_DONE();
#endif
}

#endif /* WITH_OPENSSL */
