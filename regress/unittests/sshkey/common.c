/* 	$OpenBSD: common.c,v 1.5 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/evp.h>
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
#include <openssl/rsa.h>
#endif
#include <openssl/dsa.h>
#include <openssl/objects.h>
#ifdef OPENSSL_HAS_NISTP256
# include <openssl/ec.h>
#endif /* OPENSSL_HAS_NISTP256 */
#endif /* WITH_OPENSSL */

#include "openbsd-compat/openssl-compat.h"

#include "../test_helper/test_helper.h"

#include "ssherr.h"
#include "authfile.h"
#include "sshkey.h"
#include "sshbuf.h"

#include "common.h"

struct sshbuf *
load_file(const char *name)
{
	struct sshbuf *ret = NULL;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, NULL);
	return ret;
}

struct sshbuf *
load_text_file(const char *name)
{
	struct sshbuf *ret = load_file(name);
	const u_char *p;

	/* Trim whitespace at EOL */
	for (p = sshbuf_ptr(ret); sshbuf_len(ret) > 0;) {
		if (p[sshbuf_len(ret) - 1] == '\r' ||
		    p[sshbuf_len(ret) - 1] == '\t' ||
		    p[sshbuf_len(ret) - 1] == ' ' ||
		    p[sshbuf_len(ret) - 1] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		else
			break;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	return ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(const char *name)
{
	BIGNUM *ret = NULL;
	struct sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (const char *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	return ret;
}

BIGNUM *
rsa_n(struct sshkey *k)
{
	BIGNUM *n = NULL;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
	RSA *rsa = NULL;
	BIGNUM *res = NULL;
#endif

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->pkey, NULL);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_N, &n);
	return n;
#else
	rsa = EVP_PKEY_get1_RSA(k->pkey);
	ASSERT_PTR_NE(rsa, NULL);
	RSA_get0_key(rsa, &n, NULL, NULL);
	RSA_free(rsa);
	res = BN_dup(n);
	return res;
#endif
}

BIGNUM *
rsa_e(struct sshkey *k)
{
	BIGNUM *e = NULL;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
	RSA *rsa = NULL;
	BIGNUM *res = NULL;
#endif

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->pkey, NULL);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_E, &e);
	return e;
#else
	rsa = EVP_PKEY_get1_RSA(k->pkey);
	ASSERT_PTR_NE(rsa, NULL);
	RSA_get0_key(rsa, NULL, &e, NULL);
	RSA_free(rsa);
	res = BN_dup(e);
	return res;
#endif
}

BIGNUM *
rsa_p(struct sshkey *k)
{
	BIGNUM *p = NULL;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
	RSA *rsa = NULL;
	BIGNUM *res = NULL;
#endif

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->pkey, NULL);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
	return p;
#else
	rsa = EVP_PKEY_get1_RSA(k->pkey);
	ASSERT_PTR_NE(rsa, NULL);
	RSA_get0_factors(rsa, &p, NULL);
	RSA_free(rsa);
	res = BN_dup(p);
	return res;
#endif
}

BIGNUM *
rsa_q(struct sshkey *k)
{
	BIGNUM *q = NULL;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
	RSA *rsa = NULL;
	BIGNUM *res = NULL;
#endif

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->pkey, NULL);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
	return q;
#else
	rsa = EVP_PKEY_get1_RSA(k->pkey);
	ASSERT_PTR_NE(rsa, NULL);
	RSA_get0_factors(rsa, NULL, &q);
	RSA_free(rsa);
	res = BN_dup(q);
	return res;
#endif
}

const BIGNUM *
dsa_g(struct sshkey *k)
{
	const BIGNUM *g = NULL;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->dsa, NULL);
	DSA_get0_pqg(k->dsa, NULL, NULL, &g);
	return g;
}

const BIGNUM *
dsa_pub_key(struct sshkey *k)
{
	const BIGNUM *pub_key = NULL;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->dsa, NULL);
	DSA_get0_key(k->dsa, &pub_key, NULL);
	return pub_key;
}

const BIGNUM *
dsa_priv_key(struct sshkey *k)
{
	const BIGNUM *priv_key = NULL;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->dsa, NULL);
	DSA_get0_key(k->dsa, NULL, &priv_key);
	return priv_key;
}
#endif /* WITH_OPENSSL */

