/* $OpenBSD: ssh-dss.c,v 1.49 2023/03/05 05:34:09 dtucker Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

#include "openbsd-compat/openssl-compat.h"

#define INTBLOB_LEN	20
#define SIGBLOB_LEN	(2*INTBLOB_LEN)

static u_int
ssh_dss_size(const struct sshkey *key)
{
	const BIGNUM *dsa_p;

	if (key->dsa == NULL)
		return 0;
	DSA_get0_pqg(key->dsa, &dsa_p, NULL, NULL);
	return BN_num_bits(dsa_p);
}

static int
ssh_dss_alloc(struct sshkey *k)
{
	if ((k->dsa = DSA_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	return 0;
}

static void
ssh_dss_cleanup(struct sshkey *k)
{
	DSA_free(k->dsa);
	k->dsa = NULL;
}

static int
ssh_dss_equal(const struct sshkey *a, const struct sshkey *b)
{
	const BIGNUM *dsa_p_a, *dsa_q_a, *dsa_g_a, *dsa_pub_key_a;
	const BIGNUM *dsa_p_b, *dsa_q_b, *dsa_g_b, *dsa_pub_key_b;

	if (a->dsa == NULL || b->dsa == NULL)
		return 0;
	DSA_get0_pqg(a->dsa, &dsa_p_a, &dsa_q_a, &dsa_g_a);
	DSA_get0_pqg(b->dsa, &dsa_p_b, &dsa_q_b, &dsa_g_b);
	DSA_get0_key(a->dsa, &dsa_pub_key_a, NULL);
	DSA_get0_key(b->dsa, &dsa_pub_key_b, NULL);
	if (dsa_p_a == NULL || dsa_p_b == NULL ||
	    dsa_q_a == NULL || dsa_q_b == NULL ||
	    dsa_g_a == NULL || dsa_g_b == NULL ||
	    dsa_pub_key_a == NULL || dsa_pub_key_b == NULL)
		return 0;
	if (BN_cmp(dsa_p_a, dsa_p_b) != 0)
		return 0;
	if (BN_cmp(dsa_q_a, dsa_q_b) != 0)
		return 0;
	if (BN_cmp(dsa_g_a, dsa_g_b) != 0)
		return 0;
	if (BN_cmp(dsa_pub_key_a, dsa_pub_key_b) != 0)
		return 0;
	return 1;
}

static int
ssh_dss_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;
	const BIGNUM *dsa_p, *dsa_q, *dsa_g, *dsa_pub_key;

	if (key->dsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	DSA_get0_pqg(key->dsa, &dsa_p, &dsa_q, &dsa_g);
	DSA_get0_key(key->dsa, &dsa_pub_key, NULL);
	if (dsa_p == NULL || dsa_q == NULL ||
	    dsa_g == NULL || dsa_pub_key == NULL)
		return SSH_ERR_INTERNAL_ERROR;
	if ((r = sshbuf_put_bignum2(b, dsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, dsa_q)) != 0 ||
	    (r = sshbuf_put_bignum2(b, dsa_g)) != 0 ||
	    (r = sshbuf_put_bignum2(b, dsa_pub_key)) != 0)
		return r;

	return 0;
}

static int
ssh_dss_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;
	const BIGNUM *dsa_priv_key;

	DSA_get0_key(key->dsa, NULL, &dsa_priv_key);
	if (!sshkey_is_cert(key)) {
		if ((r = ssh_dss_serialize_public(key, b, opts)) != 0)
			return r;
	}
	if ((r = sshbuf_put_bignum2(b, dsa_priv_key)) != 0)
		return r;

	return 0;
}

static int
ssh_dss_generate(struct sshkey *k, int bits)
{
	DSA *private;

	if (bits != 1024)
		return SSH_ERR_KEY_LENGTH;
	if ((private = DSA_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (!DSA_generate_parameters_ex(private, bits, NULL, 0, NULL,
	    NULL, NULL) || !DSA_generate_key(private)) {
		DSA_free(private);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	k->dsa = private;
	return 0;
}

static int
ssh_dss_copy_public(const struct sshkey *from, struct sshkey *to)
{
	const BIGNUM *dsa_p, *dsa_q, *dsa_g, *dsa_pub_key;
	BIGNUM *dsa_p_dup = NULL, *dsa_q_dup = NULL, *dsa_g_dup = NULL;
	BIGNUM *dsa_pub_key_dup = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	DSA_get0_pqg(from->dsa, &dsa_p, &dsa_q, &dsa_g);
	DSA_get0_key(from->dsa, &dsa_pub_key, NULL);
	if ((dsa_p_dup = BN_dup(dsa_p)) == NULL ||
	    (dsa_q_dup = BN_dup(dsa_q)) == NULL ||
	    (dsa_g_dup = BN_dup(dsa_g)) == NULL ||
	    (dsa_pub_key_dup = BN_dup(dsa_pub_key)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!DSA_set0_pqg(to->dsa, dsa_p_dup, dsa_q_dup, dsa_g_dup)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	dsa_p_dup = dsa_q_dup = dsa_g_dup = NULL; /* transferred */
	if (!DSA_set0_key(to->dsa, dsa_pub_key_dup, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	dsa_pub_key_dup = NULL; /* transferred */
	/* success */
	r = 0;
 out:
	BN_clear_free(dsa_p_dup);
	BN_clear_free(dsa_q_dup);
	BN_clear_free(dsa_g_dup);
	BN_clear_free(dsa_pub_key_dup);
	return r;
}

static int
ssh_dss_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *dsa_p = NULL, *dsa_q = NULL, *dsa_g = NULL, *dsa_pub_key = NULL;

	if (sshbuf_get_bignum2(b, &dsa_p) != 0 ||
	    sshbuf_get_bignum2(b, &dsa_q) != 0 ||
	    sshbuf_get_bignum2(b, &dsa_g) != 0 ||
	    sshbuf_get_bignum2(b, &dsa_pub_key) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (!DSA_set0_pqg(key->dsa, dsa_p, dsa_q, dsa_g)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	dsa_p = dsa_q = dsa_g = NULL; /* transferred */
	if (!DSA_set0_key(key->dsa, dsa_pub_key, NULL)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	dsa_pub_key = NULL; /* transferred */
#ifdef DEBUG_PK
	DSA_print_fp(stderr, key->dsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	BN_clear_free(dsa_p);
	BN_clear_free(dsa_q);
	BN_clear_free(dsa_g);
	BN_clear_free(dsa_pub_key);
	return ret;
}

static int
ssh_dss_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;
	BIGNUM *dsa_priv_key = NULL;

	if (!sshkey_is_cert(key)) {
		if ((r = ssh_dss_deserialize_public(ktype, b, key)) != 0)
			return r;
	}

	if ((r = sshbuf_get_bignum2(b, &dsa_priv_key)) != 0)
		return r;
	if (!DSA_set0_key(key->dsa, NULL, dsa_priv_key)) {
		BN_clear_free(dsa_priv_key);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	return 0;
}

static int
ssh_dss_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	EVP_PKEY *pkey = NULL;
	DSA_SIG *sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	u_char sigblob[SIGBLOB_LEN];
	size_t rlen, slen;
	int len;
	struct sshbuf *b = NULL;
	u_char *sigb = NULL;
	const u_char *psig = NULL;
	int ret = SSH_ERR_INVALID_ARGUMENT;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->dsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_DSA)
		return SSH_ERR_INVALID_ARGUMENT;

  	if ((ret = ssh_create_evp_dss(key, &pkey)) != 0)
    		return ret;
	ret = sshkey_calculate_signature(pkey, SSH_DIGEST_SHA1, &sigb, &len,
	    data, datalen);
	EVP_PKEY_free(pkey);
	if (ret < 0) {
		goto out;
	}

	psig = sigb;
	if ((sig = d2i_DSA_SIG(NULL, &psig, len)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	free(sigb);
	sigb = NULL;

	DSA_SIG_get0(sig, &sig_r, &sig_s);
	rlen = BN_num_bytes(sig_r);
	slen = BN_num_bytes(sig_s);
	if (rlen > INTBLOB_LEN || slen > INTBLOB_LEN) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	explicit_bzero(sigblob, SIGBLOB_LEN);
	BN_bn2bin(sig_r, sigblob + SIGBLOB_LEN - INTBLOB_LEN - rlen);
	BN_bn2bin(sig_s, sigblob + SIGBLOB_LEN - slen);

	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, "ssh-dss")) != 0 ||
	    (ret = sshbuf_put_string(b, sigblob, SIGBLOB_LEN)) != 0)
		goto out;

	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	free(sigb);
	DSA_SIG_free(sig);
	sshbuf_free(b);
	return ret;
}

static int
ssh_dss_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	EVP_PKEY *pkey = NULL;
	DSA_SIG *dsig = NULL;
	BIGNUM *sig_r = NULL, *sig_s = NULL;
	u_char *sigblob = NULL;
	size_t len, slen;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	char *ktype = NULL;
	u_char *sigb = NULL, *psig = NULL;

	if (key == NULL || key->dsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_DSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	/* fetch signature */
	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp("ssh-dss", ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	if (len != SIGBLOB_LEN) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* parse signature */
	if ((dsig = DSA_SIG_new()) == NULL ||
	    (sig_r = BN_new()) == NULL ||
	    (sig_s = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((BN_bin2bn(sigblob, INTBLOB_LEN, sig_r) == NULL) ||
	    (BN_bin2bn(sigblob + INTBLOB_LEN, INTBLOB_LEN, sig_s) == NULL)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (!DSA_SIG_set0(dsig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	sig_r = sig_s = NULL; /* transferred */

	if ((slen = i2d_DSA_SIG(dsig, NULL)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((sigb = malloc(slen)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	psig = sigb;
	if ((slen = i2d_DSA_SIG(dsig, &psig)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

  	if ((ret = ssh_create_evp_dss(key, &pkey)) != 0)
		goto out;
	ret = sshkey_verify_signature(pkey, SSH_DIGEST_SHA1, data, dlen,
	    sigb, slen);
	EVP_PKEY_free(pkey);

 out:
	free(sigb);
	DSA_SIG_free(dsig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	sshbuf_free(b);
	free(ktype);
	if (sigblob != NULL)
		freezero(sigblob, len);
	return ret;
}

int
ssh_create_evp_dss(const struct sshkey *k, EVP_PKEY **pkey)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  	OSSL_PARAM_BLD *param_bld = NULL;
  	EVP_PKEY_CTX *ctx = NULL;
  	const BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
  	int ret = 0;

  	if (k == NULL)
  		return SSH_ERR_INVALID_ARGUMENT;
  	if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL)) == NULL ||
  	    (param_bld = OSSL_PARAM_BLD_new()) == NULL) {
  		ret = SSH_ERR_ALLOC_FAIL;
  	  	goto out;
  	}

  	DSA_get0_pqg(k->dsa, &p, &q, &g);
  	DSA_get0_key(k->dsa, &pub, &priv);

  	if (p != NULL &&
  	    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, p) != 1) {
  		ret = SSH_ERR_LIBCRYPTO_ERROR;
  		goto out;
  	}
  	if (q != NULL &&
  	    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_Q, q) != 1) {
  		ret = SSH_ERR_LIBCRYPTO_ERROR;
  		goto out;
  	}
  	if (g != NULL &&
  	    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, g) != 1) {
  		ret = SSH_ERR_LIBCRYPTO_ERROR;
  		goto out;
  	}
  	if (pub != NULL &&
  	    OSSL_PARAM_BLD_push_BN(param_bld,
	        OSSL_PKEY_PARAM_PUB_KEY,
	        pub) != 1) {
  		ret = SSH_ERR_LIBCRYPTO_ERROR;
  		goto out;
  	}
  	if (priv != NULL &&
  	    OSSL_PARAM_BLD_push_BN(param_bld,
	        OSSL_PKEY_PARAM_PRIV_KEY,
	        priv) != 1) {
  		ret = SSH_ERR_LIBCRYPTO_ERROR;
  		goto out;
  	}
  	if ((*pkey = sshkey_create_evp(param_bld, ctx)) == NULL) {
  		ret = SSH_ERR_LIBCRYPTO_ERROR;
  		goto out;
  	}

out:
  	OSSL_PARAM_BLD_free(param_bld);
  	EVP_PKEY_CTX_free(ctx);
  	return ret;
#else
	EVP_PKEY * res = EVP_PKEY_new();
	if (res == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if (EVP_PKEY_set1_DSA(res, k->dsa) == 0) {
		EVP_PKEY_free(res);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	*pkey = res;
	return 0;
#endif
}

static const struct sshkey_impl_funcs sshkey_dss_funcs = {
	/* .size = */		ssh_dss_size,
	/* .alloc = */		ssh_dss_alloc,
	/* .cleanup = */	ssh_dss_cleanup,
	/* .equal = */		ssh_dss_equal,
	/* .ssh_serialize_public = */ ssh_dss_serialize_public,
	/* .ssh_deserialize_public = */ ssh_dss_deserialize_public,
	/* .ssh_serialize_private = */ ssh_dss_serialize_private,
	/* .ssh_deserialize_private = */ ssh_dss_deserialize_private,
	/* .generate = */	ssh_dss_generate,
	/* .copy_public = */	ssh_dss_copy_public,
	/* .sign = */		ssh_dss_sign,
	/* .verify = */		ssh_dss_verify,
};

const struct sshkey_impl sshkey_dss_impl = {
	/* .name = */		"ssh-dss",
	/* .shortname = */	"DSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_DSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_dss_funcs,
};

const struct sshkey_impl sshkey_dsa_cert_impl = {
	/* .name = */		"ssh-dss-cert-v01@openssh.com",
	/* .shortname = */	"DSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_DSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_dss_funcs,
};
#endif /* WITH_OPENSSL */
