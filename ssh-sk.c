/* $OpenBSD: ssh-sk.c,v 1.1 2019/10/31 21:16:20 djm Exp $ */
/*
 * Copyright (c) 2019 Google LLC
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

/* #define DEBUG_SK 1 */

#include "includes.h"

#ifdef ENABLE_SK

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <openssl/objects.h>
#include <openssl/ec.h>

#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "ssherr.h"
#include "digest.h"

#include "ssh-sk.h"
#include "sk-api.h"

struct sshsk_provider {
	char *path;
	void *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(void);

	/* Enroll a U2F key (private key generation) */
	int (*sk_enroll)(const uint8_t *challenge, size_t challenge_len,
	    const char *application, uint8_t flags,
	    struct sk_enroll_response **enroll_response);

	/* Sign a challenge */
	int (*sk_sign)(const uint8_t *message, size_t message_len,
	    const char *application,
	    const uint8_t *key_handle, size_t key_handle_len,
	    uint8_t flags, struct sk_sign_response **sign_response);
};

static void
sshsk_free(struct sshsk_provider *p)
{
	if (p == NULL)
		return;
	free(p->path);
	if (p->dlhandle != NULL)
		dlclose(p->dlhandle);
	free(p);
}

static struct sshsk_provider *
sshsk_open(const char *path)
{
	struct sshsk_provider *ret = NULL;
	uint32_t version;

	if ((ret = calloc(1, sizeof(*ret))) == NULL) {
		error("%s: calloc failed", __func__);
		return NULL;
	}
	if ((ret->path = strdup(path)) == NULL) {
		error("%s: strdup failed", __func__);
		goto fail;
	}
	if ((ret->dlhandle = dlopen(path, RTLD_NOW)) == NULL) {
		error("Security key provider %s dlopen failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == NULL) {
		error("Security key provider %s dlsym(sk_api_version) "
		    "failed: %s", path, dlerror());
		goto fail;
	}
	version = ret->sk_api_version();
	debug("%s: provider %s implements version 0x%08lx", __func__,
	    ret->path, (u_long)version);
	if ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Security key provider %s implements unsupported version "
		    "0x%08lx (supported: 0x%08lx)", path, (u_long)version,
		    (u_long)SSH_SK_VERSION_MAJOR);
		goto fail;
	}
	if ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == NULL) {
		error("Security key  provider %s dlsym(sk_enroll) "
		    "failed: %s", path, dlerror());
		goto fail;
	}
	if ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == NULL) {
		error("Security key provider %s dlsym(sk_sign) failed: %s",
		    path, dlerror());
		goto fail;
	}
	/* success */
	return ret;
fail:
	sshsk_free(ret);
	return NULL;
}

static void
sshsk_free_enroll_response(struct sk_enroll_response *r)
{
	if (r == NULL)
		return;
	freezero(r->key_handle, r->key_handle_len);
	freezero(r->public_key, r->public_key_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r, sizeof(*r));
};

static void
sshsk_free_sign_response(struct sk_sign_response *r)
{
	if (r == NULL)
		return;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, sizeof(*r));
};

int
sshsk_enroll(const char *provider_path, const char *application,
    uint8_t flags, struct sshbuf *challenge_buf, struct sshkey **keyp,
    struct sshbuf *attest)
{
	struct sshsk_provider *skp = NULL;
	struct sshkey *key = NULL;
	u_char randchall[32];
	const u_char *challenge;
	size_t challenge_len;
	struct sk_enroll_response *resp = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	EC_POINT *q = NULL;

	*keyp = NULL;
	if (attest)
		sshbuf_reset(attest);
	if (provider_path == NULL) {
		error("%s: missing provider", __func__);
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if (application == NULL || *application == '\0') {
		error("%s: missing application", __func__);
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if (challenge_buf == NULL) {
		debug("%s: using random challenge", __func__);
		arc4random_buf(randchall, sizeof(randchall));
		challenge = randchall;
		challenge_len = sizeof(randchall);
	} else if (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	} else {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3("%s: using explicit challenge len=%zd",
		    __func__, challenge_len);
	}
	if ((skp = sshsk_open(provider_path)) == NULL) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		goto out;
	}
	/* XXX validate flags? */
	/* enroll key */
	if ((r = skp->sk_enroll(challenge, challenge_len, application,
	    flags, &resp)) != 0) {
		error("Security key provider %s returned failure %d",
		    provider_path, r);
		r = SSH_ERR_INVALID_FORMAT; /* XXX error codes in API? */
		goto out;
	}
	/* Check response validity */
	if (resp->public_key == NULL || resp->key_handle == NULL ||
	    resp->signature == NULL || resp->attestation_cert == NULL) {
		error("%s: sk_enroll response invalid", __func__);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* Assemble key from response */
	if ((key = sshkey_new(KEY_ECDSA_SK)) == NULL) {
		error("%s: sshkey_new failed", __func__);
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	key->ecdsa_nid = NID_X9_62_prime256v1;
	key->sk_flags = flags;
	if ((key->ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid)) == NULL ||
	    (q = EC_POINT_new(EC_KEY_get0_group(key->ecdsa))) == NULL ||
	    (key->sk_key_handle = sshbuf_new()) == NULL ||
	    (key->sk_reserved = sshbuf_new()) == NULL ||
	    (b = sshbuf_new()) == NULL) {
		error("%s: allocation failed", __func__);
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_string(b,
	    resp->public_key, resp->public_key_len)) != 0) {
		error("%s: buffer error: %s", __func__, ssh_err(r));
		goto out;
	}
	if ((key->sk_application = strdup(application)) == NULL) {
		error("%s: strdup application failed", __func__);
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_get_ec(b, q, EC_KEY_get0_group(key->ecdsa))) != 0) {
		error("%s: parse key: %s", __func__, ssh_err(r));
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshkey_ec_validate_public(EC_KEY_get0_group(key->ecdsa), q) != 0) {
		error("Security key returned invalid ECDSA key");
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}
	if (EC_KEY_set_public_key(key->ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error("%s: allocation failed", __func__);
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put(key->sk_key_handle, resp->key_handle,
	    resp->key_handle_len)) != 0) {
		error("%s: buffer error: %s", __func__, ssh_err(r));
		goto out;
	}
	/* Optionally fill in the attestation information */
	if (attest != NULL) {
		if ((r = sshbuf_put_cstring(attest, "sk-attest-v00")) != 0 ||
		    (r = sshbuf_put_u32(attest, 1)) != 0 || /* XXX U2F ver */
		    (r = sshbuf_put_string(attest,
		    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
		    (r = sshbuf_put_string(attest,
		    resp->signature, resp->signature_len)) != 0 ||
		    (r = sshbuf_put_u32(attest, flags)) != 0 || /* XXX right? */
		    (r = sshbuf_put_string(attest, NULL, 0)) != 0) {
			error("%s: buffer error: %s", __func__, ssh_err(r));
			goto out;
		}
	}
	/* success */
	*keyp = key;
	key = NULL; /* transferred */
	r = 0;
 out:
	EC_POINT_free(q);
	sshsk_free(skp);
	sshbuf_free(b);
	sshkey_free(key);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, sizeof(randchall));
	return r;
}

int
sshsk_ecdsa_sign(const char *provider_path, const struct sshkey *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    u_int compat)
{
	struct sshsk_provider *skp = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sk_sign_response *resp = NULL;
	struct sshbuf *inner_sig = NULL, *sig = NULL;
	uint8_t message[32];

	if (sigp != NULL)
		*sigp = NULL;
	if (lenp != NULL)
		*lenp = 0;
	if (provider_path == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA_SK ||
	    key->sk_key_handle == NULL ||
	    key->sk_application == NULL || *key->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if ((skp = sshsk_open(provider_path)) == NULL) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		goto out;
	}

	/* hash data to be signed before it goes to the security key */
	if ((r = ssh_digest_memory(SSH_DIGEST_SHA256, data, datalen,
	    message, sizeof(message))) != 0) {
		error("%s: hash application failed: %s", __func__, ssh_err(r));
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((r = skp->sk_sign(message, sizeof(message),
	    key->sk_application,
	    sshbuf_ptr(key->sk_key_handle), sshbuf_len(key->sk_key_handle),
	    key->sk_flags, &resp)) != 0) {
		debug("%s: sk_sign failed with code %d", __func__, r);
		goto out;
	}
	if ((sig = sshbuf_new()) == NULL ||
	    (inner_sig = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* Prepare inner signature object */
	if ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0 ||
	    (r = sshbuf_put_u8(inner_sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(inner_sig, resp->counter)) != 0) {
		debug("%s: buffer error (inner): %s", __func__, ssh_err(r));
		goto out;
	}
	/* Assemble outer signature */
	if ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(key))) != 0 ||
	    (r = sshbuf_put_stringb(sig, inner_sig)) != 0) {
		debug("%s: buffer error (outer): %s", __func__, ssh_err(r));
		goto out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
	fprintf(stderr, "%s: sig_s:\n", __func__);
	sshbuf_dump_data(resp->sig_s, resp->sig_s_len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(message, sizeof(message), stderr);
	fprintf(stderr, "%s: inner:\n", __func__);
	sshbuf_dump(inner_sig, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	if (sigp != NULL) {
		if ((*sigp = malloc(sshbuf_len(sig))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	if (lenp != NULL)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	explicit_bzero(message, sizeof(message));
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	return r;
}
#endif /* ENABLE_SK */
