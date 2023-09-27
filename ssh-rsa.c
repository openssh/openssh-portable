/* $OpenBSD: ssh-rsa.c,v 1.79 2023/03/05 05:34:09 dtucker Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
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

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "digest.h"
#include "log.h"

#include "openbsd-compat/openssl-compat.h"

static int openssh_RSA_verify(int, const u_char *, size_t, u_char *, size_t, EVP_PKEY *);

static u_int
ssh_rsa_size(const struct sshkey *key)
{
	const BIGNUM *rsa_n;

	if (key->rsa == NULL)
		return 0;
	RSA_get0_key(key->rsa, &rsa_n, NULL, NULL);
	return BN_num_bits(rsa_n);
}

static int
ssh_rsa_alloc(struct sshkey *k)
{
	if ((k->rsa = RSA_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	return 0;
}

static void
ssh_rsa_cleanup(struct sshkey *k)
{
	RSA_free(k->rsa);
	k->rsa = NULL;
}

static int
ssh_rsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	const BIGNUM *rsa_e_a, *rsa_n_a;
	const BIGNUM *rsa_e_b, *rsa_n_b;

	if (a->rsa == NULL || b->rsa == NULL)
		return 0;
	RSA_get0_key(a->rsa, &rsa_n_a, &rsa_e_a, NULL);
	RSA_get0_key(b->rsa, &rsa_n_b, &rsa_e_b, NULL);
	if (rsa_e_a == NULL || rsa_e_b == NULL)
		return 0;
	if (rsa_n_a == NULL || rsa_n_b == NULL)
		return 0;
	if (BN_cmp(rsa_e_a, rsa_e_b) != 0)
		return 0;
	if (BN_cmp(rsa_n_a, rsa_n_b) != 0)
		return 0;
	return 1;
}

static int
ssh_rsa_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;
	const BIGNUM *rsa_n, *rsa_e;

	if (key->rsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	RSA_get0_key(key->rsa, &rsa_n, &rsa_e, NULL);
	if ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		return r;

	return 0;
}

static int
ssh_rsa_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;
	const BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;

	RSA_get0_key(key->rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(key->rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(key->rsa, NULL, NULL, &rsa_iqmp);

	if (!sshkey_is_cert(key)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		if ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			return r;
	}
	if ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		return r;

	return 0;
}

static int
ssh_rsa_generate(struct sshkey *k, int bits)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *res = NULL;
	BIGNUM *f4 = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		return SSH_ERR_KEY_LENGTH;

	if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) == NULL
		|| (f4 = BN_new()) == NULL || !BN_set_word(f4, RSA_F4)) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_KEY_LENGTH;
		goto out;
	}

	if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, f4) <= 0)
		goto out;

	if (EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* This function is deprecated in OpenSSL 3.0 but OpenSSH doesn't worry about it*/
	k->rsa = EVP_PKEY_get1_RSA(res);
	if (k->rsa) {
		ret = 0;
	} else {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
 out:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(res);
	BN_free(f4);
	return ret;
}

static int
ssh_rsa_copy_public(const struct sshkey *from, struct sshkey *to)
{
	const BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = NULL, *rsa_e_dup = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	RSA_get0_key(from->rsa, &rsa_n, &rsa_e, NULL);
	if ((rsa_n_dup = BN_dup(rsa_n)) == NULL ||
	    (rsa_e_dup = BN_dup(rsa_e)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!RSA_set0_key(to->rsa, rsa_n_dup, rsa_e_dup, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_n_dup = rsa_e_dup = NULL; /* transferred */
	/* success */
	r = 0;
 out:
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	return r;
}

static int
ssh_rsa_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = NULL, *rsa_e = NULL;

	if (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (!RSA_set0_key(key->rsa, rsa_n, rsa_e, NULL)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_n = rsa_e = NULL; /* transferred */
	if ((ret = sshkey_check_rsa_length(key, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	RSA_print_fp(stderr, key->rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	return ret;
}

static int
ssh_rsa_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;
	BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
	BIGNUM *rsa_iqmp = NULL, *rsa_p = NULL, *rsa_q = NULL;

	/* Note: can't reuse ssh_rsa_deserialize_public: e, n vs. n, e */
	if (!sshkey_is_cert(key)) {
		if ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			goto out;
		if (!RSA_set0_key(key->rsa, rsa_n, rsa_e, NULL)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		rsa_n = rsa_e = NULL; /* transferred */
	}
	if ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		goto out;
	if (!RSA_set0_key(key->rsa, NULL, NULL, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_d = NULL; /* transferred */
	if (!RSA_set0_factors(key->rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_p = rsa_q = NULL; /* transferred */
	if ((r = sshkey_check_rsa_length(key, 0)) != 0)
		goto out;
	if ((r = ssh_rsa_complete_crt_parameters(key, rsa_iqmp)) != 0)
		goto out;
	if (RSA_blinding_on(key->rsa, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	BN_clear_free(rsa_d);
	BN_clear_free(rsa_p);
	BN_clear_free(rsa_q);
	BN_clear_free(rsa_iqmp);
	return r;
}

static const char *
rsa_hash_alg_ident(int hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		return "ssh-rsa";
	case SSH_DIGEST_SHA256:
		return "rsa-sha2-256";
	case SSH_DIGEST_SHA512:
		return "rsa-sha2-512";
	}
	return NULL;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
static int
rsa_hash_id_from_ident(const char *ident)
{
	if (strcmp(ident, "ssh-rsa") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(ident, "rsa-sha2-256") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(ident, "rsa-sha2-512") == 0)
		return SSH_DIGEST_SHA512;
	return -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
static int
rsa_hash_id_from_keyname(const char *alg)
{
	int r;

	if ((r = rsa_hash_id_from_ident(alg)) != -1)
		return r;
	if (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA512;
	return -1;
}

int
ssh_rsa_complete_crt_parameters(struct sshkey *key, const BIGNUM *iqmp)
{
	const BIGNUM *rsa_p, *rsa_q, *rsa_d;
	BIGNUM *aux = NULL, *d_consttime = NULL;
	BIGNUM *rsa_dmq1 = NULL, *rsa_dmp1 = NULL, *rsa_iqmp = NULL;
	BN_CTX *ctx = NULL;
	int r;

	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;

	RSA_get0_key(key->rsa, NULL, NULL, &rsa_d);
	RSA_get0_factors(key->rsa, &rsa_p, &rsa_q);

	if ((ctx = BN_CTX_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((aux = BN_new()) == NULL ||
	    (rsa_dmq1 = BN_new()) == NULL ||
	    (rsa_dmp1 = BN_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((d_consttime = BN_dup(rsa_d)) == NULL ||
	    (rsa_iqmp = BN_dup(iqmp)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	if ((BN_sub(aux, rsa_q, BN_value_one()) == 0) ||
	    (BN_mod(rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_value_one()) == 0) ||
	    (BN_mod(rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (!RSA_set0_crt_params(key->rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = NULL; /* transferred */
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_clear_free(rsa_dmp1);
	BN_clear_free(rsa_dmq1);
	BN_clear_free(rsa_iqmp);
	BN_CTX_free(ctx);
	return r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
static int
ssh_rsa_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	EVP_PKEY *pkey = NULL;
	u_char *sig = NULL;
	int len, slen = 0;
	int hash_alg, ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (alg == NULL || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	else
		hash_alg = rsa_hash_id_from_keyname(alg);

	if (key == NULL || key->rsa == NULL || hash_alg == -1 ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;
	slen = RSA_size(key->rsa);
	if (RSA_bits(key->rsa) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;

#ifdef ENABLE_PKCS11
	if (is_rsa_pkcs11(key->rsa)) {
		if ((pkey = EVP_PKEY_new()) == NULL ||
		    EVP_PKEY_set1_RSA(pkey, key->rsa) != 1)
			return SSH_ERR_ALLOC_FAIL;
	} else {
#endif
		if ((ret = ssh_create_evp_rsa(key, &pkey)) != 0)
			return ret;
#ifdef ENABLE_PKCS11
	}
#endif
	ret = sshkey_calculate_signature(pkey, hash_alg, &sig, &len, data,
	    datalen);
	EVP_PKEY_free(pkey);
	if (ret < 0) {
		goto out;
	}

	if (len < slen) {
		size_t diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} else if (len > slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
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
	freezero(sig, slen);
	sshbuf_free(b);
	return ret;
}

static int
ssh_rsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	EVP_PKEY *pkey = NULL;
	char *sigtype = NULL;
	int hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen;
	struct sshbuf *b = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = NULL;

	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if (RSA_bits(key->rsa) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &sigtype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	if (alg != NULL && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		if ((want_alg = rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			goto out;
		}
	}
	if (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = RSA_size(key->rsa);
	if (len > modlen) {
		ret = SSH_ERR_KEY_BITS_MISMATCH;
		goto out;
	} else if (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		if ((sigblob = realloc(sigblob, modlen)) == NULL) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

  	if ((ret = ssh_create_evp_rsa(key, &pkey)) != 0)
		goto out;

	ret = openssh_RSA_verify(hash_alg, data, dlen, sigblob, len, pkey);
	EVP_PKEY_free(pkey);

 out:
	freezero(sigblob, len);
	free(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, sizeof(digest));
	return ret;
}

static int
openssh_RSA_verify(int hash_alg, const u_char *data, size_t datalen,
    u_char *sigbuf, size_t siglen, EVP_PKEY *pkey)
{
	size_t rsasize = 0;
	int ret;

	rsasize = EVP_PKEY_get_size(pkey);
	if (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    siglen == 0 || siglen > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}

	ret = sshkey_verify_signature(pkey, hash_alg, data, datalen,
	    sigbuf, siglen);

done:
	return ret;
}

int
ssh_create_evp_rsa(const struct sshkey *k, EVP_PKEY **pkey)
{
  	OSSL_PARAM_BLD *param_bld = NULL;
  	EVP_PKEY_CTX *ctx = NULL;
  	int ret = 0;
  	const BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
  	const BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

  	if (k == NULL)
  	  	return SSH_ERR_INVALID_ARGUMENT;
  	if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) == NULL ||
  	    (param_bld = OSSL_PARAM_BLD_new()) == NULL) {
  	  	ret = SSH_ERR_ALLOC_FAIL;
  	  	goto out;
  	}

  	RSA_get0_key(k->rsa, &n, &e, &d);
  	RSA_get0_factors(k->rsa, &p, &q);
  	RSA_get0_crt_params(k->rsa, &dmp1, &dmq1, &iqmp);

  	if (n != NULL &&
  	    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n) != 1) {
  	  	ret = SSH_ERR_LIBCRYPTO_ERROR;
  		goto out;
  	}
  	if (e != NULL &&
  	    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
  	}
  	if (d != NULL &&
  	    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_D, d) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
  	}

  	if ((*pkey = sshkey_create_evp(param_bld, ctx)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
  	}

  	/* setting this to param_build makes the creation process fail */
  	if (p != NULL &&
  	    EVP_PKEY_set_bn_param(*pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, p) != 1) {
		debug2_f("failed to add 'p' param");
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
  	}
  	if (q != NULL &&
  	    EVP_PKEY_set_bn_param(*pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, q) != 1) {
		debug2_f("failed to add 'q' param");
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
  	}
  	if (dmp1 != NULL &&
  	    EVP_PKEY_set_bn_param(*pkey,
  	        OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1) != 1) {
		debug2_f("failed to add 'dmp1' param");
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
  	}
  	if (dmq1 != NULL &&
  	    EVP_PKEY_set_bn_param(*pkey,
  	        OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1) != 1) {
		debug2_f("failed to add 'dmq1' param");
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
  	}
  	if (iqmp != NULL &&
  	    EVP_PKEY_set_bn_param(*pkey,
  	        OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp) != 1) {
		debug2_f("failed to add 'iqmp' param");
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
  	}

out:
  	OSSL_PARAM_BLD_free(param_bld);
  	EVP_PKEY_CTX_free(ctx);
  	return ret;
}

static const struct sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_size,
	/* .alloc = */		ssh_rsa_alloc,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_private,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_public,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};

const struct sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

const struct sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#endif /* WITH_OPENSSL */
