/* $Id: openssl-compat.c,v 1.17 2014/02/13 05:38:33 dtucker Exp $ */

/*
 * Copyright (c) 2005 Darren Tucker <dtucker@zip.com.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <stdarg.h>
#include <string.h>

#ifdef USE_OPENSSL_ENGINE
# include <openssl/engine.h>
# include <openssl/conf.h>
#endif

#ifndef HAVE_RSA_GET_DEFAULT_METHOD
# include <wolfssl/openssl/rsa.h>
#endif

#include "log.h"

#define SSH_DONT_OVERLOAD_WOLFSSL_FUNCS
#include "wolfssl-compat.h"

#ifdef SSH_OLD_EVP
int
ssh_EVP_CipherInit(EVP_CIPHER_CTX *evp, const EVP_CIPHER *type,
    unsigned char *key, unsigned char *iv, int enc)
{
	EVP_CipherInit(evp, type, key, iv, enc);
	return 1;
}

int
ssh_EVP_Cipher(EVP_CIPHER_CTX *evp, char *dst, char *src, int len)
{
	EVP_Cipher(evp, dst, src, len);
	return 1;
}

int
ssh_EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *evp)
{
	EVP_CIPHER_CTX_cleanup(evp);
	return 1;
}
#endif

#ifndef HAVE_EVP_DIGESTINIT_EX
int
EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *md, void *engine)
{
	if (engine != NULL)
		fatal("%s: ENGINE is not supported", __func__);
# ifdef WOLFSSL_EVP_DIGESTUPDATE_VOID
	EVP_DigestInit(ctx, md);
	return 1;
# else
	return EVP_DigestInit(ctx, md);
# endif
}
#endif

#ifndef HAVE_EVP_DIGESTFINAL_EX
int
EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
{
# ifdef WOLFSSL_EVP_DIGESTUPDATE_VOID
	EVP_DigestFinal(ctx, md, s);
	return 1;
# else
	return EVP_DigestFinal(ctx, md, s);
# endif
}
#endif

#ifdef WOLFSSL_EVP_DIGESTUPDATE_VOID
int
ssh_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt)
{
	EVP_DigestUpdate(ctx, d, cnt);
	return 1;
}
#endif

#ifndef HAVE_BN_IS_PRIME_EX
int
BN_is_prime_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, void *cb)
{
	if (cb != NULL)
		fatal("%s: callback args not supported", __func__);
	return BN_is_prime(p, nchecks, NULL, ctx, NULL);
}
#endif

#ifndef HAVE_RSA_GENERATE_KEY_EX
int
RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *bn_e, void *cb)
{
	RSA *new_rsa, tmp_rsa;
	unsigned long e;

	if (cb != NULL)
		fatal("%s: callback args not supported", __func__);
	e = BN_get_word(bn_e);
	if (e == 0xffffffffL)
		fatal("%s: value of e too large", __func__);
	new_rsa = RSA_generate_key(bits, e, NULL, NULL);
	if (new_rsa == NULL)
		return 0;
	/* swap rsa/new_rsa then free new_rsa */
	tmp_rsa = *rsa;
	*rsa = *new_rsa;
	*new_rsa = tmp_rsa;
	RSA_free(new_rsa);
	return 1;
}
#endif

#ifndef HAVE_DSA_GENERATE_PARAMETERS_EX
int
DSA_generate_parameters_ex(DSA *dsa, int bits, const unsigned char *seed,
    int seed_len, int *counter_ret, unsigned long *h_ret, void *cb)
{
	DSA *new_dsa, tmp_dsa;

	if (cb != NULL)
		fatal("%s: callback args not supported", __func__);
	new_dsa = DSA_generate_parameters(bits, (unsigned char *)seed, seed_len,
	    counter_ret, h_ret, NULL, NULL);
	if (new_dsa == NULL)
		return 0;
	/* swap dsa/new_dsa then free new_dsa */
	tmp_dsa = *dsa;
	*dsa = *new_dsa;
	*new_dsa = tmp_dsa;
	DSA_free(new_dsa);
	return 1;
}
#endif

#ifndef HAVE_RSA_GET_DEFAULT_METHOD
RSA_METHOD *
RSA_get_default_method(void)
{
	return RSA_PKCS1_SSLeay();
}
#endif
