/* $OpenBSD: kexecdh.c,v 1.10 2019/01/21 10:40:11 djm Exp $ */
/*
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "log.h"

static int
kex_ecdh_dec_key_group(struct kex *kex, const struct sshbuf *ec_blob,
    EVP_PKEY *pkey, struct sshbuf **shared_secretp);

static EVP_PKEY *
generate_ec_keys(int ec_nid)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	OSSL_PARAM_BLD *param_bld = NULL;
	OSSL_PARAM *params = NULL;
	const char *group_name;

	if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL ||
	    (param_bld = OSSL_PARAM_BLD_new()) == NULL)
		goto out;
	if ((group_name = OSSL_EC_curve_nid2name(ec_nid)) == NULL ||
	    OSSL_PARAM_BLD_push_utf8_string(param_bld,
	        OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0) != 1 ||
	    (params = OSSL_PARAM_BLD_to_param(param_bld)) == NULL) {
		error_f("Could not create OSSL_PARAM");
		goto out;
	}
	if (EVP_PKEY_keygen_init(ctx) != 1 ||
	    EVP_PKEY_CTX_set_params(ctx, params) != 1 ||
	    EVP_PKEY_generate(ctx, &pkey) != 1) {
		error_f("Could not generate ec keys");
		goto out;
	}
#else
	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL ||
	    EVP_PKEY_keygen_init(ctx) != 1 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, ec_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) != 1) {
		error_f("Could not generate ec keys");
		goto out;
	}
#endif
out:
	EVP_PKEY_CTX_free(ctx);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	OSSL_PARAM_BLD_free(param_bld);
	OSSL_PARAM_free(params);
#endif
	return pkey;
}

int
kex_ecdh_keypair(struct kex *kex)
{
	EVP_PKEY *client_key = NULL;
	struct sshbuf *buf = NULL;
	int r;

	if ((client_key = generate_ec_keys(kex->ec_nid)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_ec(buf, client_key)) != 0 ||
	    (r = sshbuf_get_u32(buf, NULL)) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_key(client_key);
#endif
	kex->pkey = client_key;
	client_key = NULL;	/* owned by the kex */
	kex->client_pub = buf;
	buf = NULL;
out:
	EVP_PKEY_free(client_key);
	sshbuf_free(buf);
	return r;
}

int
kex_ecdh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	EVP_PKEY *server_key = NULL;
	struct sshbuf *server_blob = NULL;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if ((server_key = generate_ec_keys(kex->ec_nid)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_key(server_key);
#endif
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_ec(server_blob, server_key)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, NULL)) != 0)
		goto out;
	if ((r = kex_ecdh_dec_key_group(kex, client_blob, server_key,
	    shared_secretp)) != 0)
		goto out;
	*server_blobp = server_blob;
	server_blob = NULL;
out:
	EVP_PKEY_free(server_key);
	sshbuf_free(server_blob);
	return r;
}

static int
kex_ecdh_dec_key_group(struct kex *kex, const struct sshbuf *ec_blob,
    EVP_PKEY *pkey, struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	BIGNUM *shared_secret = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *peer_key = NULL;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	OSSL_PARAM_BLD *param_bld = NULL;
	OSSL_PARAM *params = NULL;
	const char *group_name;
#else
	EC_KEY *ec = NULL;
#endif
	u_char *kbuf = NULL, *pub = NULL;
	size_t klen = 0, publen;
	int r;

	*shared_secretp = NULL;

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		goto out;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	if ((r = sshbuf_get_string(buf, &pub, &publen)) != 0)
		goto out;
	sshbuf_reset(buf);
	if ((group_name = OSSL_EC_curve_nid2name(kex->ec_nid)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((param_bld = OSSL_PARAM_BLD_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (OSSL_PARAM_BLD_push_octet_string(param_bld,
	        OSSL_PKEY_PARAM_PUB_KEY, pub, publen) != 1 ||
	    OSSL_PARAM_BLD_push_utf8_string(param_bld,
	        OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0) != 1 ||
	    (params = OSSL_PARAM_BLD_to_param(param_bld)) == NULL) {
		error_f("Failed to set params for peer_key");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EVP_PKEY_fromdata_init(ctx) != 1 ||
	    EVP_PKEY_fromdata(ctx, &peer_key,
	        EVP_PKEY_PUBLIC_KEY, params) != 1 ||
	    EVP_PKEY_public_check(ctx) != 1) {
		error_f("Peer public key import failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#else
	if ((ec = EC_KEY_new_by_curve_name(kex->ec_nid)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_get_eckey(buf, ec)) != 0)
		goto out;

	if ((peer_key = EVP_PKEY_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (EVP_PKEY_set1_EC_KEY(peer_key, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#endif

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	EVP_PKEY_print_public_fp(stderr, peer_key, 0, NULL);
#endif
	EVP_PKEY_CTX_free(ctx);
	ctx = NULL;
	if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL ||
	    EVP_PKEY_derive_init(ctx) != 1 ||
	    EVP_PKEY_derive_set_peer(ctx, peer_key) != 1 ||
	    EVP_PKEY_derive(ctx, NULL, &klen) != 1) {
		error_f("Failed to get derive information");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((kbuf = malloc(klen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_derive(ctx, kbuf, &klen) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	if ((shared_secret = BN_new()) == NULL ||
	    (BN_bin2bn(kbuf, klen, shared_secret) == NULL)) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
		goto out;
	*shared_secretp = buf;
	buf = NULL;
 out:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peer_key);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	OSSL_PARAM_BLD_free(param_bld);
	OSSL_PARAM_free(params);
#else
	EC_KEY_free(ec);
#endif
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	freezero(pub, publen);
	sshbuf_free(buf);
	return r;
}

int
kex_ecdh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	int r;

	r = kex_ecdh_dec_key_group(kex, server_blob, kex->pkey,
	    shared_secretp);
	EVP_PKEY_free(kex->pkey);
	kex->pkey = NULL;
	return r;
}

#else

#include "ssherr.h"

struct kex;
struct sshbuf;
struct sshkey;

int
kex_ecdh_keypair(struct kex *kex)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
kex_ecdh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
kex_ecdh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC) */
