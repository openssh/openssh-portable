/* $OpenBSD: kexc25519.c,v 1.3 2014/01/09 23:20:00 djm Exp $ */
/*
 * Copyright (c) 2001, 2013 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2013 Aris Adamantiadis.  All rights reserved.
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

#include <sys/types.h>

#include <signal.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include "buffer.h"
#include "ssh2.h"
#include "key.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "digest.h"

extern int crypto_scalarmult_curve25519(u_char a[CURVE25519_SIZE],
    const u_char b[CURVE25519_SIZE], const u_char c[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_SIZE)));

void
kexc25519_keygen(u_char key[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
{
	static const u_char basepoint[CURVE25519_SIZE] = {9};

	arc4random_buf(key, CURVE25519_SIZE);
	crypto_scalarmult_curve25519(pub, key, basepoint);
}

BIGNUM *
kexc25519_shared_key(const u_char key[CURVE25519_SIZE],
    const u_char pub[CURVE25519_SIZE])
{
	u_char shared_key[CURVE25519_SIZE];
	BIGNUM *shared_secret;

	crypto_scalarmult_curve25519(shared_key, key, pub);
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", shared_key, CURVE25519_SIZE);
#endif
	if ((shared_secret = BN_new()) == NULL)
		fatal("%s: BN_new failed", __func__);
	if (BN_bin2bn(shared_key, sizeof(shared_key), shared_secret) == NULL)
		fatal("%s: BN_bin2bn failed", __func__);
	memset(shared_key, 0, CURVE25519_SIZE);	/* XXX explicit_bzero() */
	return (shared_secret);
}

void
kex_c25519_hash(
    int hash_alg,
    char *client_version_string,
    char *server_version_string,
    char *ckexinit, int ckexinitlen,
    char *skexinit, int skexinitlen,
    u_char *serverhostkeyblob, int sbloblen,
    const u_char client_dh_pub[CURVE25519_SIZE],
    const u_char server_dh_pub[CURVE25519_SIZE],
    const BIGNUM *shared_secret,
    u_char **hash, u_int *hashlen)
{
	Buffer b;
	static u_char digest[SSH_DIGEST_MAX_LENGTH];

	buffer_init(&b);
	buffer_put_cstring(&b, client_version_string);
	buffer_put_cstring(&b, server_version_string);

	/* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	buffer_put_int(&b, ckexinitlen+1);
	buffer_put_char(&b, SSH2_MSG_KEXINIT);
	buffer_append(&b, ckexinit, ckexinitlen);
	buffer_put_int(&b, skexinitlen+1);
	buffer_put_char(&b, SSH2_MSG_KEXINIT);
	buffer_append(&b, skexinit, skexinitlen);

	buffer_put_string(&b, serverhostkeyblob, sbloblen);
	buffer_put_string(&b, client_dh_pub, CURVE25519_SIZE);
	buffer_put_string(&b, server_dh_pub, CURVE25519_SIZE);
	buffer_put_bignum2(&b, shared_secret);

#ifdef DEBUG_KEX
	buffer_dump(&b);
#endif
	if (ssh_digest_buffer(hash_alg, &b, digest, sizeof(digest)) != 0)
		fatal("%s: digest_buffer failed", __func__);

	buffer_free(&b);

#ifdef DEBUG_KEX
	dump_digest("hash", digest, ssh_digest_bytes(hash_alg));
#endif
	*hash = digest;
	*hashlen = ssh_digest_bytes(hash_alg);
}
