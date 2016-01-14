/* $Id: openssl-compat.h,v 1.31 2014/08/29 18:18:29 djm Exp $ */

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

#ifndef USING_WOLFSSL

#ifndef _OPENSSL_COMPAT_H
#define _OPENSSL_COMPAT_H

#include "includes.h"
#ifdef WITH_OPENSSL

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

int ssh_compatible_openssl(long, long);

#if (OPENSSL_VERSION_NUMBER <= 0x0090805fL)
# error OpenSSL 0.9.8f or greater is required
#endif

#if OPENSSL_VERSION_NUMBER < 0x10000001L
# define LIBCRYPTO_EVP_INL_TYPE unsigned int
#else
# define LIBCRYPTO_EVP_INL_TYPE size_t
#endif

#ifndef OPENSSL_RSA_MAX_MODULUS_BITS
# define OPENSSL_RSA_MAX_MODULUS_BITS	16384
#endif
#ifndef OPENSSL_DSA_MAX_MODULUS_BITS
# define OPENSSL_DSA_MAX_MODULUS_BITS	10000
#endif

#ifndef OPENSSL_HAVE_EVPCTR
# define EVP_aes_128_ctr evp_aes_128_ctr
# define EVP_aes_192_ctr evp_aes_128_ctr
# define EVP_aes_256_ctr evp_aes_128_ctr
const EVP_CIPHER *evp_aes_128_ctr(void);
void ssh_aes_ctr_iv(EVP_CIPHER_CTX *, int, u_char *, size_t);
#endif

/* Avoid some #ifdef. Code that uses these is unreachable without GCM */
#if !defined(OPENSSL_HAVE_EVPGCM) && !defined(EVP_CTRL_GCM_SET_IV_FIXED)
# define EVP_CTRL_GCM_SET_IV_FIXED -1
# define EVP_CTRL_GCM_IV_GEN -1
# define EVP_CTRL_GCM_SET_TAG -1
# define EVP_CTRL_GCM_GET_TAG -1
#endif

/* Replace missing EVP_CIPHER_CTX_ctrl() with something that returns failure */
#ifndef HAVE_EVP_CIPHER_CTX_CTRL
# ifdef OPENSSL_HAVE_EVPGCM
#  error AES-GCM enabled without EVP_CIPHER_CTX_ctrl /* shouldn't happen */
# else
# define EVP_CIPHER_CTX_ctrl(a,b,c,d) (0)
# endif
#endif

/*
 * We overload some of the OpenSSL crypto functions with ssh_* equivalents
 * to automatically handle OpenSSL engine initialisation.
 *
 * In order for the compat library to call the real functions, it must
 * define SSH_DONT_OVERLOAD_OPENSSL_FUNCS before including this file and
 * implement the ssh_* equivalents.
 */
#ifndef SSH_DONT_OVERLOAD_OPENSSL_FUNCS

# ifdef USE_OPENSSL_ENGINE
#  ifdef OpenSSL_add_all_algorithms
#   undef OpenSSL_add_all_algorithms
#  endif
#  define OpenSSL_add_all_algorithms()  ssh_OpenSSL_add_all_algorithms()
# endif

void ssh_OpenSSL_add_all_algorithms(void);

#endif	/* SSH_DONT_OVERLOAD_OPENSSL_FUNCS */

#endif /* WITH_OPENSSL */
#endif /* _OPENSSL_COMPAT_H */
#endif /* USING_WOLFSSL */
