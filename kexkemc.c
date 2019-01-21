/* $OpenBSD: kexkemc.c,v 1.3 2019/01/21 10:28:02 djm Exp $ */
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
#include "log.h"
#include "packet.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

static int
input_kex_kem_reply(int type, u_int32_t seq, struct ssh *ssh);

int
kex_kem_client(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	int r;

	switch (kex->kex_type) {
	case KEX_DH_GRP1_SHA1:
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
	case KEX_DH_GRP16_SHA512:
	case KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		break;
	case KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		break;
	case KEX_KEM_SNTRUP4591761X25519_SHA512:
		r = kex_kem_sntrup4591761x25519_keypair(kex);
		break;
	default:
		r = SSH_ERR_INVALID_ARGUMENT;
		break;
	}
	if (r != 0)
		return r;
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->kem_client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		return r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_ECDH_REPLY, &input_kex_kem_reply);
	return 0;
}

static int
input_kex_kem_reply(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	struct sshkey *server_host_key = NULL;
	struct sshbuf *shared_secret = NULL;
	u_char *server_pubkey = NULL;
	u_char *server_host_key_blob = NULL, *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, pklen, sbloblen, hashlen;
	int r;

	/* hostkey */
	if ((r = sshpkt_get_string(ssh, &server_host_key_blob,
	    &sbloblen)) != 0 ||
	    (r = sshkey_from_blob(server_host_key_blob, sbloblen,
	    &server_host_key)) != 0)
		goto out;
	if ((r = kex_verify_host_key(ssh, server_host_key)) != 0)
		goto out;

	/* Q_S, server public key */
	/* signed H */
	if ((r = sshpkt_get_string(ssh, &server_pubkey, &pklen)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;

	/* compute shared secret */
	switch (kex->kex_type) {
	case KEX_DH_GRP1_SHA1:
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
	case KEX_DH_GRP16_SHA512:
	case KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_pubkey, pklen, &shared_secret);
		break;
	case KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_pubkey, pklen, &shared_secret);
		break;
	case KEX_KEM_SNTRUP4591761X25519_SHA512:
		r = kex_kem_sntrup4591761x25519_dec(kex, server_pubkey, pklen,
		    &shared_secret);
		break;
	default:
		r = SSH_ERR_INVALID_ARGUMENT;
		break;
	}
	if (r !=0 )
		goto out;

	/* calc and verify H */
	hashlen = sizeof(hash);
	if ((r = kex_c25519_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    sshbuf_ptr(kex->my), sshbuf_len(kex->my),
	    sshbuf_ptr(kex->peer), sshbuf_len(kex->peer),
	    server_host_key_blob, sbloblen,
	    sshbuf_ptr(kex->kem_client_pub), sshbuf_len(kex->kem_client_pub),
	    server_pubkey, pklen,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		goto out;

	if ((r = sshkey_verify(server_host_key, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat)) != 0)
		goto out;

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);
out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(kex->c25519_client_key, sizeof(kex->c25519_client_key));
	explicit_bzero(kex->sntrup4591761_client_key,
	    sizeof(kex->sntrup4591761_client_key));
	free(server_host_key_blob);
	free(server_pubkey);
	free(signature);
	sshkey_free(server_host_key);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->kem_client_pub);
	kex->kem_client_pub = NULL;
	return r;
}
