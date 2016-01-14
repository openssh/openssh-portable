/* $Id: openssl-compat.h,v 1.26 2014/02/13 05:38:33 dtucker Exp $ */

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
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/rsa.h>
#include <wolfssl/openssl/dsa.h>

/* Only in 0.9.8 */
#ifndef OPENSSL_DSA_MAX_MODULUS_BITS
# define OPENSSL_DSA_MAX_MODULUS_BITS        10000
#endif
#ifndef OPENSSL_RSA_MAX_MODULUS_BITS
# define OPENSSL_RSA_MAX_MODULUS_BITS        16384
#endif

# define LIBCRYPTO_EVP_INL_TYPE size_t

/* Replace missing EVP_CIPHER_CTX_ctrl() with something that returns failure */
#ifndef HAVE_EVP_CIPHER_CTX_CTRL
# ifdef OPENSSL_HAVE_EVPGCM
#  error AES-GCM enabled without EVP_CIPHER_CTX_ctrl /* shouldn't happen */
# else
# define EVP_CIPHER_CTX_ctrl(a,b,c,d) (0)
# endif
#endif

#define EVP_X_STATE(evp)	wolfSSL_EVP_X_STATE(&(evp))
#define EVP_X_STATE_LEN(evp)	wolfSSL_EVP_X_STATE_LEN(&(evp))

#ifndef HAVE_RSA_GET_DEFAULT_METHOD
RSA_METHOD *RSA_get_default_method(void);
#endif

# ifdef OPENSSL_EVP_DIGESTUPDATE_VOID
#  define EVP_DigestUpdate(a,b,c)	ssh_EVP_DigestUpdate((a),(b),(c))
#  endif

# ifndef HAVE_BN_IS_PRIME_EX
int BN_is_prime_ex(const BIGNUM *, int, BN_CTX *, void *);
# endif

# ifndef HAVE_DSA_GENERATE_PARAMETERS_EX
int DSA_generate_parameters_ex(DSA *, int, const unsigned char *, int, int *,
    unsigned long *, void *);
# endif

# ifndef HAVE_RSA_GENERATE_KEY_EX
int RSA_generate_key_ex(RSA *, int, BIGNUM *, void *);
# endif

# ifndef HAVE_EVP_DIGESTINIT_EX
int EVP_DigestInit_ex(EVP_MD_CTX *, const EVP_MD *, void *);
# endif

# ifndef HAVE_EVP_DISESTFINAL_EX
int EVP_DigestFinal_ex(EVP_MD_CTX *, unsigned char *, unsigned int *);
# endif

int ssh_EVP_CipherInit(EVP_CIPHER_CTX *, const EVP_CIPHER *, unsigned char *,
    unsigned char *, int);
int ssh_EVP_Cipher(EVP_CIPHER_CTX *, char *, char *, int);
int ssh_EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *);
void ssh_OpenSSL_add_all_algorithms(void);

# ifndef HAVE_HMAC_CTX_INIT
#  define HMAC_CTX_init(a)
# endif

# ifndef HAVE_EVP_MD_CTX_INIT
#  define EVP_MD_CTX_init(a)
# endif

# ifndef HAVE_EVP_MD_CTX_CLEANUP
#  define EVP_MD_CTX_cleanup(a)
# endif

