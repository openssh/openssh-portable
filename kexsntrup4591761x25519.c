/* $OpenBSD: kexsntrup4591761x25519.c,v 1.1 2019/01/21 10:20:12 djm Exp $ */
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

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

int
kex_kem_sntrup4591761x25519_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	u_char *cp = NULL;
	size_t need;
	int r;

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_sntrup4591761_PUBLICKEYBYTES + CURVE25519_SIZE;
	if ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		goto out;
	crypto_kem_sntrup4591761_keypair(cp, kex->sntrup4591761_client_key);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key sntrup4591761:", cp,
	    crypto_kem_sntrup4591761_PUBLICKEYBYTES);
#endif
	cp += crypto_kem_sntrup4591761_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_key, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->kem_client_pub = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	return r;
}

int
kex_kem_sntrup4591761x25519_enc(struct kex *kex, const u_char *pkblob,
   size_t pklen, struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	struct sshbuf *server_blob = NULL;
	struct sshbuf *buf = NULL;
	u_char *kem_key, *ciphertext, *server_pub;
	u_char server_key[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	/* pkblob contains both KEM and ECDH client pubkeys */
	need = crypto_kem_sntrup4591761_PUBLICKEYBYTES + CURVE25519_SIZE;
	if (pklen != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key sntrup4591761:", pkblob,
	    crypto_kem_sntrup4591761_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    pkblob + crypto_kem_sntrup4591761_PUBLICKEYBYTES, CURVE25519_SIZE);
#endif
	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_reserve(buf, crypto_kem_sntrup4591761_BYTES,
	    &kem_key)) != 0)
		goto out;
	/* allocate space for encrypted KEM key and ECDH pub key */
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	need = crypto_kem_sntrup4591761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	if ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		goto out;
	/* generate and encrypt KEM key with client key */
	crypto_kem_sntrup4591761_enc(ciphertext, kem_key, pkblob);
	/* generate ECDH key pair, store server pubkey after ciphertext */
	server_pub = ciphertext + crypto_kem_sntrup4591761_CIPHERTEXTBYTES;
	kexc25519_keygen(server_key, server_pub);
	/* append ECDH shared key */
	if ((r = kexc25519_shared_key_ext(server_key,
	    pkblob + crypto_kem_sntrup4591761_PUBLICKEYBYTES, buf, 1)) < 0)
		goto out;
	if ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, sizeof(hash))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup4591761_CIPHERTEXTBYTES);
	dump_digest("server kem key:", kem_key, sizeof(kem_key));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	if ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = NULL;
	buf = NULL;
 out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(server_key, sizeof(server_key));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	return r;
}

int
kex_kem_sntrup4591761x25519_dec(struct kex *kex, const u_char *pkblob,
    size_t pklen, struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	u_char *kem_key = NULL;
	const u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	int r, decoded;

	*shared_secretp = NULL;

	need = crypto_kem_sntrup4591761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	if (pklen != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	ciphertext = pkblob;
	server_pub = pkblob + crypto_kem_sntrup4591761_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup4591761_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_reserve(buf, crypto_kem_sntrup4591761_BYTES,
	    &kem_key)) != 0)
		goto out;
	decoded = crypto_kem_sntrup4591761_dec(kem_key, ciphertext,
	    kex->sntrup4591761_client_key);
	if ((r = kexc25519_shared_key_ext(kex->c25519_client_key, server_pub,
	    buf, 1)) < 0)
		goto out;
	if ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, sizeof(hash))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", kem_key, sizeof(kem_key));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	if ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	if (decoded != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	*shared_secretp = buf;
	buf = NULL;
 out:
	explicit_bzero(hash, sizeof(hash));
	sshbuf_free(buf);
	return r;
}
