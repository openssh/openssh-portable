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

/* Pure ML-DSA-87 (FIPS 204) signatures: ssh-mldsa-87 */

#include "includes.h"

#ifdef USE_MLDSA

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "crypto_api.h"
#include "sshbuf.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "log.h"

#define SSH_MLDSA87_ALG_NAME	"ssh-mldsa-87"

static void
ssh_mldsa87_cleanup(struct sshkey *k)
{
	freezero(k->mldsa87_pk, MLDSA87_PUBLICKEYBYTES);
	freezero(k->mldsa87_sk, MLDSA87_SECRETKEYBYTES);
	k->mldsa87_pk = NULL;
	k->mldsa87_sk = NULL;
}

static int
ssh_mldsa87_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a->mldsa87_pk == NULL || b->mldsa87_pk == NULL)
		return 0;
	if (memcmp(a->mldsa87_pk, b->mldsa87_pk, MLDSA87_PUBLICKEYBYTES) != 0)
		return 0;
	return 1;
}

static int
ssh_mldsa87_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if (key->mldsa87_pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshbuf_put_string(b, key->mldsa87_pk,
	    MLDSA87_PUBLICKEYBYTES)) != 0)
		return r;

	return 0;
}

static int
ssh_mldsa87_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if (key->mldsa87_sk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!sshkey_is_cert(key)) {
		if ((r = ssh_mldsa87_serialize_public(key, b, opts)) != 0)
			return r;
	}
	if ((r = sshbuf_put_string(b, key->mldsa87_sk,
	    MLDSA87_SECRETKEYBYTES)) != 0)
		return r;

	return 0;
}

static int
ssh_mldsa87_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	u_char *pk = NULL;
	size_t len = 0;
	int r;

	if ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		return r;
	if (len != MLDSA87_PUBLICKEYBYTES) {
		freezero(pk, len);
		return SSH_ERR_INVALID_FORMAT;
	}
	key->mldsa87_pk = pk;
	return 0;
}

static int
ssh_mldsa87_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;
	size_t sklen = 0;
	u_char *sk = NULL;

	if (!sshkey_is_cert(key)) {
		if ((r = ssh_mldsa87_deserialize_public(ktype, b, key)) != 0)
			return r;
	}
	if ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		goto out;
	if (sklen != MLDSA87_SECRETKEYBYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	key->mldsa87_sk = sk;
	sk = NULL; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	return r;
}

static int
ssh_mldsa87_generate(struct sshkey *k, int bits)
{
	ssh_mldsa87_cleanup(k);
	if ((k->mldsa87_pk = malloc(MLDSA87_PUBLICKEYBYTES)) == NULL ||
	    (k->mldsa87_sk = malloc(MLDSA87_SECRETKEYBYTES)) == NULL) {
		ssh_mldsa87_cleanup(k);
		return SSH_ERR_ALLOC_FAIL;
	}
	if (crypto_sign_mldsa87_keypair(k->mldsa87_pk, k->mldsa87_sk) != 0) {
		ssh_mldsa87_cleanup(k);
		return SSH_ERR_CRYPTO_ERROR;
	}
	return 0;
}

static int
ssh_mldsa87_copy_public(const struct sshkey *from, struct sshkey *to)
{
	if (from->mldsa87_pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((to->mldsa87_pk = malloc(MLDSA87_PUBLICKEYBYTES)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	memcpy(to->mldsa87_pk, from->mldsa87_pk, MLDSA87_PUBLICKEYBYTES);
	return 0;
}

static int
ssh_mldsa87_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA87_SIGBYTES];
	struct sshbuf *b = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_MLDSA87 ||
	    key->mldsa87_sk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if (crypto_sign_mldsa87(sig, data, datalen, NULL, 0,
	    key->mldsa87_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		goto out;
	}

	if ((b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_cstring(b, SSH_MLDSA87_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, sizeof(sig))) != 0)
		goto out;

	if (sigp != NULL) {
		if ((*sigp = malloc(sshbuf_len(b))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	if (lenp != NULL)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, sizeof(sig));
	return r;
}

static int
ssh_mldsa87_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen, const u_char *data, size_t dlen,
    const char *alg, u_int compat, struct sshkey_sig_details **detailsp)
{
	struct sshbuf *b = NULL;
	char *ktype = NULL;
	const u_char *sigblob;
	size_t len;
	int r;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_MLDSA87 ||
	    key->mldsa87_pk == NULL ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_get_cstring(b, &ktype, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		goto out;
	if (strcmp(SSH_MLDSA87_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if (len != MLDSA87_SIGBYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if (crypto_sign_mldsa87_verify(sigblob, data, dlen, NULL, 0,
	    key->mldsa87_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	free(ktype);
	return r;
}

const struct sshkey_impl_funcs sshkey_mldsa87_funcs = {
	/* .size = */		NULL,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_mldsa87_cleanup,
	/* .equal = */		ssh_mldsa87_equal,
	/* .ssh_serialize_public = */ ssh_mldsa87_serialize_public,
	/* .ssh_deserialize_public = */ ssh_mldsa87_deserialize_public,
	/* .ssh_serialize_private = */ ssh_mldsa87_serialize_private,
	/* .ssh_deserialize_private = */ ssh_mldsa87_deserialize_private,
	/* .generate = */	ssh_mldsa87_generate,
	/* .copy_public = */	ssh_mldsa87_copy_public,
	/* .sign = */		ssh_mldsa87_sign,
	/* .verify = */		ssh_mldsa87_verify,
};

const struct sshkey_impl sshkey_mldsa87_impl = {
	/* .name = */		"ssh-mldsa-87",
	/* .shortname = */	"MLDSA87",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_MLDSA87,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_mldsa87_funcs,
};

const struct sshkey_impl sshkey_mldsa87_cert_impl = {
	/* .name = */		"ssh-mldsa87-cert-v01@openssh.com",
	/* .shortname = */	"MLDSA87-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_MLDSA87_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_mldsa87_funcs,
};
#endif /* USE_MLDSA */
