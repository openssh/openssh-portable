/*
 * Copyright (c) 2026 OpenSSH contributors
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

/*
 * Pure ML-KEM-1024 (FIPS 203) key agreement: "mlkem1024-sha384".
 *
 * This backend uses the native ML-KEM implementation in OpenSSL 3.5 and
 * later, via the generic EVP_PKEY KEM interface (EVP_PKEY_encapsulate /
 * EVP_PKEY_decapsulate with key type "ML-KEM-1024"). It is only compiled
 * when built against OpenSSL >= 3.5.0 (see USE_MLKEM1024_EVP in defines.h);
 * otherwise the stubs at the bottom of this file return
 * SSH_ERR_SIGN_ALG_UNSUPPORTED and the method is not offered.
 *
 * The shared secret is the SHA-384 hash of the ML-KEM shared key, encoded
 * as an SSH string, matching the framing used by the other KEM kex methods.
 */

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "log.h"

#ifdef USE_MLKEM1024_EVP

#include <openssl/evp.h>
#include <openssl/core_names.h>

#define MLKEM1024_NAME		"ML-KEM-1024"
/* FIPS 203 ML-KEM-1024 wire sizes */
#define MLKEM1024_PUBLICKEYBYTES	1568
#define MLKEM1024_CIPHERTEXTBYTES	1568
#define MLKEM1024_SHAREDSECRETBYTES	32

/* Create an ML-KEM-1024 EVP_PKEY context. */
static EVP_PKEY_CTX *
mlkem1024_ctx(void)
{
	return EVP_PKEY_CTX_new_from_name(NULL, MLKEM1024_NAME, NULL);
}

int
kex_kem_mlkem1024_keypair(struct kex *kex)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	struct sshbuf *buf = NULL;
	u_char *cp = NULL;
	size_t pklen = 0;
	int r = SSH_ERR_INTERNAL_ERROR;

	/* Generate the client ML-KEM keypair. */
	if ((ctx = mlkem1024_ctx()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_keygen_init(ctx) != 1 ||
	    EVP_PKEY_keygen(ctx, &pkey) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* Extract the encoded public key. */
	if (EVP_PKEY_get_octet_string_param(pkey,
	    OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pklen) != 1 ||
	    pklen != MLKEM1024_PUBLICKEYBYTES) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_reserve(buf, pklen, &cp)) != 0)
		goto out;
	if (EVP_PKEY_get_octet_string_param(pkey,
	    OSSL_PKEY_PARAM_PUB_KEY, cp, pklen, &pklen) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem1024:", cp,
	    MLKEM1024_PUBLICKEYBYTES);
#endif
	/* Keep the private key for kex_kem_mlkem1024_dec(). */
	EVP_PKEY_free(kex->mlkem1024_client_key);
	kex->mlkem1024_client_key = pkey;
	pkey = NULL;

	/* success */
	r = 0;
	kex->client_pub = buf;
	buf = NULL;
 out:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	sshbuf_free(buf);
	return r;
}

int
kex_kem_mlkem1024_enc(struct kex *kex,
   const struct sshbuf *client_blob, struct sshbuf **server_blobp,
   struct sshbuf **shared_secretp)
{
	EVP_PKEY_CTX *fromctx = NULL, *encctx = NULL;
	EVP_PKEY *client_pkey = NULL;
	OSSL_PARAM params[2];
	struct sshbuf *server_blob = NULL;
	struct sshbuf *buf = NULL;
	const u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char *ct = NULL;
	u_char shared_secret[MLKEM1024_SHAREDSECRETBYTES];
	size_t ctlen = 0, sslen = 0;
	int r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	/* client_blob is the ML-KEM public key */
	if (sshbuf_len(client_blob) != MLKEM1024_PUBLICKEYBYTES) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem1024:", client_pub,
	    MLKEM1024_PUBLICKEYBYTES);
#endif

	/* Import the client's public key into an EVP_PKEY. */
	params[0] = OSSL_PARAM_construct_octet_string(
	    OSSL_PKEY_PARAM_PUB_KEY,
	    (void *)client_pub, MLKEM1024_PUBLICKEYBYTES);
	params[1] = OSSL_PARAM_construct_end();
	if ((fromctx = mlkem1024_ctx()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_fromdata_init(fromctx) != 1 ||
	    EVP_PKEY_fromdata(fromctx, &client_pkey, EVP_PKEY_PUBLIC_KEY,
	    params) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* Encapsulate against the client's public key. */
	if ((encctx = EVP_PKEY_CTX_new_from_pkey(NULL, client_pkey,
	    NULL)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_encapsulate_init(encctx, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* Query output sizes. */
	if (EVP_PKEY_encapsulate(encctx, NULL, &ctlen, NULL, &sslen) != 1 ||
	    ctlen != MLKEM1024_CIPHERTEXTBYTES ||
	    sslen != MLKEM1024_SHAREDSECRETBYTES) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((ct = malloc(ctlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_encapsulate(encctx, ct, &ctlen, shared_secret,
	    &sslen) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* Hash the KEM shared key to form the SSH shared secret. */
	if ((buf = sshbuf_new()) == NULL ||
	    (server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put(buf, shared_secret, sslen)) != 0 ||
	    (r = sshbuf_put(server_blob, ct, ctlen)) != 0)
		goto out;
	if ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, sizeof(hash))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, ctlen);
	dump_digest("server kem key:", shared_secret, sslen);
#endif
	sshbuf_reset(buf);
	if ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		goto out;

	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = NULL;
	buf = NULL;
 out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(shared_secret, sizeof(shared_secret));
	if (ct != NULL)
		freezero(ct, ctlen);
	EVP_PKEY_free(client_pkey);
	EVP_PKEY_CTX_free(fromctx);
	EVP_PKEY_CTX_free(encctx);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	return r;
}

int
kex_kem_mlkem1024_dec(struct kex *kex,
    const struct sshbuf *server_blob, struct sshbuf **shared_secretp)
{
	EVP_PKEY_CTX *decctx = NULL;
	struct sshbuf *buf = NULL;
	const u_char *ciphertext;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char shared_secret[MLKEM1024_SHAREDSECRETBYTES];
	size_t sslen = 0;
	int r = SSH_ERR_INTERNAL_ERROR;

	*shared_secretp = NULL;

	if (kex->mlkem1024_client_key == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if (sshbuf_len(server_blob) != MLKEM1024_CIPHERTEXTBYTES) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	ciphertext = sshbuf_ptr(server_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    MLKEM1024_CIPHERTEXTBYTES);
#endif

	/* Decapsulate with the client private key kept from keypair(). */
	if ((decctx = EVP_PKEY_CTX_new_from_pkey(NULL,
	    kex->mlkem1024_client_key, NULL)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_decapsulate_init(decctx, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EVP_PKEY_decapsulate(decctx, NULL, &sslen, ciphertext,
	    MLKEM1024_CIPHERTEXTBYTES) != 1 ||
	    sslen != MLKEM1024_SHAREDSECRETBYTES) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EVP_PKEY_decapsulate(decctx, shared_secret, &sslen, ciphertext,
	    MLKEM1024_CIPHERTEXTBYTES) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put(buf, shared_secret, sslen)) != 0)
		goto out;
	if ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, sizeof(hash))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, sslen);
#endif
	sshbuf_reset(buf);
	if ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		goto out;

	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = NULL;
 out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(shared_secret, sizeof(shared_secret));
	EVP_PKEY_CTX_free(decctx);
	EVP_PKEY_free(kex->mlkem1024_client_key);
	kex->mlkem1024_client_key = NULL;
	sshbuf_free(buf);
	return r;
}

#else /* USE_MLKEM1024_EVP */

int
kex_kem_mlkem1024_keypair(struct kex *kex)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
kex_kem_mlkem1024_enc(struct kex *kex,
   const struct sshbuf *client_blob, struct sshbuf **server_blobp,
   struct sshbuf **shared_secretp)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
kex_kem_mlkem1024_dec(struct kex *kex,
    const struct sshbuf *server_blob, struct sshbuf **shared_secretp)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

#endif /* USE_MLKEM1024_EVP */
