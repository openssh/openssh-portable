/* $OpenBSD$ */
/*
 * Copyright (c) 2026 OpenSSH contributors
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * OpenSSL-based implementation of ML-DSA-87 (FIPS 204) crypto_sign API.
 * Alternative to the internal libcrux-based implementation in
 * libcrux-mlkem-mldsa.c.  Used when OpenSSL >= 3.5 provides ML-DSA-87.
 */

#include "includes.h"

#ifdef OPENSSL_HAS_MLDSA87

#include <sys/types.h>

#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/core_names.h>

#include "crypto_api.h"
#include "log.h"

int
crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	size_t pklen, sklen;
	int ret = -1;

	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ML_DSA_87, NULL)) == NULL) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		goto out;
	}
	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		goto out;
	}
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		goto out;
	}

	/* Extract public key */
	pklen = MLDSA87_PUBLICKEYBYTES;
	if (!EVP_PKEY_get_raw_public_key(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		goto out;
	}
	if (pklen != MLDSA87_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		goto out;
	}

	/* Extract private key (full expanded secret key) */
	sklen = MLDSA87_SECRETKEYBYTES;
	if (!EVP_PKEY_get_raw_private_key(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		goto out;
	}
	if (sklen != MLDSA87_SECRETKEYBYTES) {
		debug3_f("private key length mismatch: %zu", sklen);
		goto out;
	}

	ret = 0;
 out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

int
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    const uint8_t *msg, size_t msglen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	OSSL_PARAM params[2], *p = params;
	size_t siglen;
	int ret = -1;

	/* Import the secret key */
	if ((pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ML_DSA_87, NULL,
	    sk, MLDSA87_SECRETKEYBYTES)) == NULL) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		goto out;
	}

	if ((mdctx = EVP_MD_CTX_new()) == NULL) {
		debug3_f("EVP_MD_CTX_new failed");
		goto out;
	}
	if (EVP_DigestSignInit(mdctx, &pctx, NULL, NULL, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		goto out;
	}

	/* Set context string if provided (FIPS 204 context) */
	if (ctx != NULL && ctxlen > 0) {
		*p++ = OSSL_PARAM_construct_octet_string(
		    OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
		    (void *)ctx, ctxlen);
		*p = OSSL_PARAM_construct_end();
		if (EVP_PKEY_CTX_set_params(pctx, params) != 1) {
			debug3_f("EVP_PKEY_CTX_set_params (context) failed");
			goto out;
		}
	}

	siglen = MLDSA87_SIGBYTES;
	if (EVP_DigestSign(mdctx, sig, &siglen, msg, msglen) != 1) {
		debug3_f("EVP_DigestSign failed");
		goto out;
	}
	if (siglen != MLDSA87_SIGBYTES) {
		debug3_f("signature length mismatch: %zu", siglen);
		goto out;
	}

	ret = 0;
 out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	return ret;
}

int
crypto_sign_mldsa87_verify(const uint8_t sig[MLDSA87_SIGBYTES],
    const uint8_t *msg, size_t msglen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	OSSL_PARAM params[2], *p = params;
	int ret = -1;

	/* Import the public key */
	if ((pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ML_DSA_87, NULL,
	    pk, MLDSA87_PUBLICKEYBYTES)) == NULL) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		goto out;
	}

	if ((mdctx = EVP_MD_CTX_new()) == NULL) {
		debug3_f("EVP_MD_CTX_new failed");
		goto out;
	}
	if (EVP_DigestVerifyInit(mdctx, &pctx, NULL, NULL, pkey) != 1) {
		debug3_f("EVP_DigestVerifyInit failed");
		goto out;
	}

	/* Set context string if provided (FIPS 204 context) */
	if (ctx != NULL && ctxlen > 0) {
		*p++ = OSSL_PARAM_construct_octet_string(
		    OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
		    (void *)ctx, ctxlen);
		*p = OSSL_PARAM_construct_end();
		if (EVP_PKEY_CTX_set_params(pctx, params) != 1) {
			debug3_f("EVP_PKEY_CTX_set_params (context) failed");
			goto out;
		}
	}

	if (EVP_DigestVerify(mdctx, sig, MLDSA87_SIGBYTES,
	    msg, msglen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		goto out;
	}

	ret = 0;
 out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	return ret;
}

#endif /* OPENSSL_HAS_MLDSA87 */
