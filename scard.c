/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#ifdef SMARTCARD
#include "includes.h"
RCSID("$OpenBSD: scard.c,v 1.4 2001/07/02 22:40:17 markus Exp $");

#include <openssl/engine.h>
#include <sectok.h>

#include "key.h"
#include "log.h"
#include "xmalloc.h"
#include "scard.h"

#define CLA_SSH 0x05
#define INS_DECRYPT 0x10
#define INS_GET_KEYLENGTH 0x20
#define INS_GET_PUBKEY 0x30
#define INS_GET_RESPONSE 0xc0

#define MAX_BUF_SIZE 256

static int sc_fd = -1;
static int sc_reader_num = 0;
static int cla = 0x00;	/* class */

/* interface to libsectok */

static int 
sc_open(int num)
{
	u_char atr[256];
	int sw;

	if (sc_fd >= 0)
		return sc_fd;
	sc_reader_num = num;

	sc_fd = sectok_open(sc_reader_num, 0, NULL);
	if (sc_fd < 0) {
		error("sectok_open failed %d", sc_fd);
		return sc_fd;
	}
	if (sectok_reset(sc_fd, 0, atr, &sw) <= 0) {
		error("sectok_reset failed: %s", sectok_get_sw(sw));
		sc_fd = -1;
		return sc_fd;
	}
	debug("sc_open ok %d", sc_fd);
	return sc_fd;
}

static int 
sc_enable_applet(void)
{
	u_char contID[2], aid[MAX_BUF_SIZE];
	int i, len, sw, aid_len;

	len = sw = 0;
	contID[0] = 0x77;
	contID[1] = 0x78;

	if (sectok_selectfile(sc_fd, cla, root_fid, &sw) < 0) {
		error("sectok_selectfile root_fid failed: %s",
		    sectok_get_sw(sw));
		return -1;
	}
	if (sectok_selectfile(sc_fd, cla, contID, &sw) < 0) {
		error("sectok_selectfile failed: %s", sectok_get_sw(sw));
		return -1;
	}
	/* send appled id */
	for (i = 0; i < sizeof(aid); i++)
		aid[i] = 0x77;
	aid_len = 5;
	sectok_apdu(sc_fd, cla, 0xa4, 0x04, 0, aid_len, aid, 0, NULL, &sw);
	if (!sectok_swOK(sw)) {
		error("sectok_apdu failed: %s", sectok_get_sw(sw));
		return -1;
	}
	return 0;
}

static int 
sc_read_pubkey(Key * k)
{
	u_char buf[2], *n;
	char *p;
	int len, sw;

	len = sw = 0;

	/* get key size */
	sectok_apdu(sc_fd, CLA_SSH, INS_GET_KEYLENGTH, 0, 0, 0, NULL,
	     sizeof(buf), buf, &sw);
	if (!sectok_swOK(sw)) {
		error("could not obtain key length: %s", sectok_get_sw(sw));
		return -1;
	}
	len = (buf[0] << 8) | buf[1];
	len /= 8;
	debug("INS_GET_KEYLENGTH: len %d sw %s", len, sectok_get_sw(sw));

	n = xmalloc(len);
	/* get n */
	sectok_apdu(sc_fd, CLA_SSH, INS_GET_PUBKEY, 0, 0, 0, NULL, len, n, &sw);
	if (!sectok_swOK(sw)) {
		error("could not obtain public key: %s", sectok_get_sw(sw));
		xfree(n);
		return -1;
	}
	debug("INS_GET_KEYLENGTH: sw %s", sectok_get_sw(sw));

	if (BN_bin2bn(n, len, k->rsa->n) == NULL) {
		error("c_read_pubkey: BN_bin2bn failed");
		xfree(n);
		return -1;
	}
	xfree(n);

	/* currently the java applet just stores 'n' */
	if (!BN_set_word(k->rsa->e, 35)) {
		error("c_read_pubkey: BN_set_word(e, 35) failed");
		return -1;
	}

	p = key_fingerprint(k, SSH_FP_MD5, SSH_FP_HEX);
	debug("fingerprint %d %s", key_size(k), p);
	xfree(p);

	return 0;
}

/* private key operations */

static int
sc_private_decrypt(int flen, u_char *from, u_char *to, RSA *rsa, int padding)
{
	u_char *padded = NULL;
	int sw, len, olen;

	debug("sc_private_decrypt called");

	olen = len = sw = 0;
	if (padding != RSA_PKCS1_PADDING)
		goto err;

	len = BN_num_bytes(rsa->n);
	padded = xmalloc(len);

	sectok_apdu(sc_fd, CLA_SSH, INS_DECRYPT, 0, 0, len, from, 0, NULL, &sw);
	if (!sectok_swOK(sw)) {
		error("sc_private_decrypt: INS_DECRYPT failed: %s",
		    sectok_get_sw(sw));
		goto err;
	}
	sectok_apdu(sc_fd, CLA_SSH, INS_GET_RESPONSE, 0, 0, 0, NULL,
	     len, padded, &sw);
	if (!sectok_swOK(sw)) {
		error("sc_private_decrypt: INS_GET_RESPONSE failed: %s",
		    sectok_get_sw(sw));
		goto err;
	}
	olen = RSA_padding_check_PKCS1_type_2(to, len, padded + 1, len - 1,
	    len);
err:
	if (padded)
		xfree(padded);
	return olen;
}

static int
sc_private_encrypt(int flen, u_char *from, u_char *to, RSA *rsa, int padding)
{
	u_char *padded = NULL;
	int sw, len;

	len = sw = 0;
	if (padding != RSA_PKCS1_PADDING)
		goto err;

	debug("sc_private_encrypt called");
	len = BN_num_bytes(rsa->n);
	padded = xmalloc(len);

	if (RSA_padding_add_PKCS1_type_1(padded, len, from, flen) <= 0) {
		error("RSA_padding_add_PKCS1_type_1 failed");
		goto err;
	}
	sectok_apdu(sc_fd, CLA_SSH, INS_DECRYPT, 0, 0, len, padded, 0, NULL, &sw);
	if (!sectok_swOK(sw)) {
		error("sc_private_decrypt: INS_DECRYPT failed: %s",
		    sectok_get_sw(sw));
		goto err;
	}
	sectok_apdu(sc_fd, CLA_SSH, INS_GET_RESPONSE, 0, 0, 0, NULL,
	     len, to, &sw);
	if (!sectok_swOK(sw)) {
		error("sc_private_decrypt: INS_GET_RESPONSE failed: %s",
		    sectok_get_sw(sw));
		goto err;
	}
err:
	if (padded)
		xfree(padded);
	return len;
}

/* engine for overloading private key operations */

static ENGINE *smart_engine = NULL;
static RSA_METHOD smart_rsa =
{
	"sectok",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	NULL,
};

ENGINE *
sc_get_engine(void)
{
	RSA_METHOD *def;

	def = RSA_get_default_openssl_method();

	/* overload */
	smart_rsa.rsa_priv_enc	= sc_private_encrypt;
	smart_rsa.rsa_priv_dec	= sc_private_decrypt;

	/* just use the OpenSSL version */
	smart_rsa.rsa_pub_enc   = def->rsa_pub_enc;
	smart_rsa.rsa_pub_dec   = def->rsa_pub_dec;
	smart_rsa.rsa_mod_exp	= def->rsa_mod_exp;
	smart_rsa.bn_mod_exp	= def->bn_mod_exp;
	smart_rsa.init		= def->init;
	smart_rsa.finish	= def->finish;
	smart_rsa.flags		= def->flags;
	smart_rsa.app_data	= def->app_data;
	smart_rsa.rsa_sign	= def->rsa_sign;
	smart_rsa.rsa_verify	= def->rsa_verify;

	smart_engine = ENGINE_new();

	ENGINE_set_id(smart_engine, "sectok");
	ENGINE_set_name(smart_engine, "libsectok");
	ENGINE_set_RSA(smart_engine, &smart_rsa);
	ENGINE_set_DSA(smart_engine, DSA_get_default_openssl_method());
	ENGINE_set_DH(smart_engine, DH_get_default_openssl_method());
	ENGINE_set_RAND(smart_engine, RAND_SSLeay());
	ENGINE_set_BN_mod_exp(smart_engine, BN_mod_exp);

	return smart_engine;
}

Key *
sc_get_key(int sc_reader_num)
{
	Key *k;

	if (sc_open(sc_reader_num) < 0) {
		error("sc_open failed");
		return NULL;
	}
	if (sc_enable_applet() < 0) {
		error("sc_enable_applet failed");
		return NULL;
	}
	k = key_new(KEY_RSA);
	if (k == NULL) {
		return NULL;
	}
	if (sc_read_pubkey(k) < 0) {
		error("sc_read_pubkey failed");
		key_free(k);
		return NULL;
	}
	return k;
}
#endif
