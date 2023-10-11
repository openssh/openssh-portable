/* $OpenBSD: kexdh.c,v 1.34 2020/12/04 02:29:25 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "openbsd-compat/openssl-compat.h"
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "dh.h"
#include "log.h"

int
kex_dh_keygen(struct kex *kex)
{
	switch (kex->kex_type) {
	case KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		break;
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		break;
	case KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		break;
	case KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		break;
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (kex->dh == NULL)
		return SSH_ERR_ALLOC_FAIL;
	return (dh_gen_key(kex->dh, kex->we_need * 8));
}

int
kex_dh_compute_key(struct kex *kex, BIGNUM *dh_pub, struct sshbuf *out)
{
	BIGNUM *shared_secret = NULL;
	const BIGNUM *pub, *priv, *p, *q, *g;
	EVP_PKEY *pkey = NULL, *dh_pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	u_char *kbuf = NULL;
	size_t klen = 0;
	int r = 0;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
	DH *dh_peer = NULL;
	BIGNUM *copy_p = NULL, *copy_q = NULL, *copy_g = NULL, *copy_pub = NULL;
#endif

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_num_bits(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#endif

	if (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	DH_get0_key(kex->dh, &pub, &priv);
	DH_get0_pqg(kex->dh, &p, &q, &g);
	/* import key */
	r = kex_create_evp_dh(&pkey, p, q, g, pub, priv);
	if (r != 0) {
		error_f("Could not create EVP_PKEY for dh");
		ERR_print_errors_fp(stderr);
		goto out;
	}
	/* import peer key
	 * the parameters should be the same as with pkey
	 */
	r = kex_create_evp_dh(&dh_pkey, p, q, g, dh_pub, NULL);
	if (r != 0) {
		error_f("Could not import peer key for dh");
		ERR_print_errors_fp(stderr);
		goto out;
	}
#else
	DH_get0_pqg(kex->dh, &p, &q, &g);
	if ((pkey = EVP_PKEY_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (EVP_PKEY_set1_DH(pkey, kex->dh) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((dh_peer = DH_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	copy_p = BN_dup(p);
	copy_q = BN_dup(q);
	copy_g = BN_dup(g);
	if (DH_set0_pqg(dh_peer, copy_p, copy_q, copy_g) != 1) {
		BN_free(copy_p);
		BN_free(copy_q);
		BN_free(copy_g);
		DH_free(dh_peer);
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	copy_p = copy_q = copy_g = NULL;

	copy_pub = BN_dup(dh_pub);
	if (DH_set0_key(dh_peer, copy_pub, NULL) != 1) {
		BN_free(copy_pub);
		DH_free(dh_peer);
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	copy_pub = NULL;

	if ((dh_pkey = EVP_PKEY_new()) == NULL) {
		DH_free(dh_peer);
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (EVP_PKEY_set1_DH(dh_pkey, dh_peer) != 1) {
		DH_free(dh_peer);
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	DH_free(dh_peer);
#endif

	if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
		error_f("Could not init EVP_PKEY_CTX for dh");
		ERR_print_errors_fp(stderr);
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_derive_init(ctx) != 1 ||
	    EVP_PKEY_derive_set_peer(ctx, dh_pkey) != 1 ||
	    EVP_PKEY_derive(ctx, NULL, &klen) != 1) {
		error_f("Could not get key size");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((kbuf = malloc(klen)) == NULL ||
	    (shared_secret = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_derive(ctx, kbuf, &klen) != 1 ||
	    BN_bin2bn(kbuf, klen, shared_secret) == NULL) {
		error_f("Could not derive key");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, klen);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	EVP_PKEY_free(pkey);
	EVP_PKEY_free(dh_pkey);
	EVP_PKEY_CTX_free(ctx);
	return r;
}

int
kex_dh_keypair(struct kex *kex)
{
	const BIGNUM *pub_key;
	struct sshbuf *buf = NULL;
	int r;

	if ((r = kex_dh_keygen(kex)) != 0)
		return r;
	DH_get0_key(kex->dh, &pub_key, NULL);
	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_put_bignum2(buf, pub_key)) != 0 ||
	    (r = sshbuf_get_u32(buf, NULL)) != 0)
		goto out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_key);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	return r;
}

int
kex_dh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	const BIGNUM *pub_key;
	struct sshbuf *server_blob = NULL;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if ((r = kex_dh_keygen(kex)) != 0)
		goto out;
	DH_get0_key(kex->dh, &pub_key, NULL);
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_bignum2(server_blob, pub_key)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, NULL)) != 0)
		goto out;
	if ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		goto out;
	*server_blobp = server_blob;
	server_blob = NULL;
 out:
	DH_free(kex->dh);
	kex->dh = NULL;
	sshbuf_free(server_blob);
	return r;
}

int
kex_dh_dec(struct kex *kex, const struct sshbuf *dh_blob,
    struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	BIGNUM *dh_pub = NULL;
	int r;

	*shared_secretp = NULL;

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		goto out;
	sshbuf_reset(buf);
	if ((r = kex_dh_compute_key(kex, dh_pub, buf)) != 0)
		goto out;
	*shared_secretp = buf;
	buf = NULL;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = NULL;
	sshbuf_free(buf);
	return r;
}
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
/* 
 * Creates an EVP_PKEY from the given parameters and keys.
 * The private key can be omitted.
 */
int
kex_create_evp_dh(EVP_PKEY **pkey, const BIGNUM *p, const BIGNUM *q,
    const BIGNUM *g, const BIGNUM *pub, const BIGNUM *priv)
{
	OSSL_PARAM_BLD *param_bld = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int r = 0;

	/* create EVP_PKEY-DH key */
	if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)) == NULL ||
	    (param_bld = OSSL_PARAM_BLD_new()) == NULL) {
		error_f("EVP_PKEY_CTX or PARAM_BLD init failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, p) != 1 ||
	    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_Q, q) != 1 ||
	    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, g) != 1 ||
	    OSSL_PARAM_BLD_push_BN(param_bld,
	        OSSL_PKEY_PARAM_PUB_KEY, pub) != 1) {
		error_f("Failed pushing params to OSSL_PARAM_BLD");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (priv != NULL &&
	    OSSL_PARAM_BLD_push_BN(param_bld,
	        OSSL_PKEY_PARAM_PRIV_KEY, priv) != 1) {
		error_f("Failed pushing private key to OSSL_PARAM_BLD");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((*pkey = sshkey_create_evp(param_bld, ctx)) == NULL)
		r = SSH_ERR_LIBCRYPTO_ERROR;
out:
	OSSL_PARAM_BLD_free(param_bld);
	EVP_PKEY_CTX_free(ctx);
	return r;
}
#endif
#endif /* WITH_OPENSSL */
