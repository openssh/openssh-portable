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

#include "includes.h"
#ifdef SMARTCARD
RCSID("$OpenBSD: scard.c,v 1.20 2002/03/21 16:57:15 markus Exp $");
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <sectok.h>

#include "key.h"
#include "log.h"
#include "xmalloc.h"
#include "scard.h"
#include "readpass.h"

#ifdef OPENSSL_VERSION_NUMBER
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
#define RSA_get_default_openssl_method RSA_get_default_method
#define DSA_get_default_openssl_method DSA_get_default_method
#define DH_get_default_openssl_method DH_get_default_method
#define ENGINE_set_BN_mod_exp(x,y)
#endif
#endif

#define CLA_SSH 0x05
#define INS_DECRYPT 0x10
#define INS_GET_KEYLENGTH 0x20
#define INS_GET_PUBKEY 0x30
#define INS_GET_RESPONSE 0xc0

#define MAX_BUF_SIZE 256

static int sc_fd = -1;
static char *sc_reader_id = NULL;
static int cla = 0x00;	/* class */

/* interface to libsectok */

static int
sc_open(void)
{
	int sw;

	if (sc_fd >= 0)
		return sc_fd;

	sc_fd = sectok_friendly_open(sc_reader_id, STONOWAIT, &sw);
	if (sc_fd < 0) {
		error("sectok_open failed: %s", sectok_get_sw(sw));
		return SCARD_ERROR_FAIL;
	}
	if (! sectok_cardpresent(sc_fd)) {
		debug("smartcard in reader %s not present, skipping",
		    sc_reader_id);
		sc_close();
		return SCARD_ERROR_NOCARD;
	}
	if (sectok_reset(sc_fd, 0, NULL, &sw) <= 0) {
		error("sectok_reset failed: %s", sectok_get_sw(sw));
		sc_fd = -1;
		return SCARD_ERROR_FAIL;
	}
	if ((cla = cyberflex_inq_class(sc_fd)) < 0)
		cla = 0;

	debug("sc_open ok %d", sc_fd);
	return sc_fd;
}

static int
sc_enable_applet(void)
{
	static u_char aid[] = {0xfc, 0x53, 0x73, 0x68, 0x2e, 0x62, 0x69, 0x6e};
	int sw = 0;

	/* select applet id */
	sectok_apdu(sc_fd, cla, 0xa4, 0x04, 0, sizeof aid, aid, 0, NULL, &sw);
	if (!sectok_swOK(sw)) {
		error("sectok_apdu failed: %s", sectok_get_sw(sw));
		sc_close();
		return -1;
	}
	return 0;
}

static int
sc_init(void)
{
	int status;

	status = sc_open();
	if (status == SCARD_ERROR_NOCARD) {
		return SCARD_ERROR_NOCARD;
	}
	if (status < 0 ) {
		error("sc_open failed");
		return status;
	}
	if (sc_enable_applet() < 0) {
		error("sc_enable_applet failed");
		return SCARD_ERROR_APPLET;
	}
	return 0;
}

static int
sc_read_pubkey(Key * k)
{
	u_char buf[2], *n;
	char *p;
	int len, sw, status = -1;

	len = sw = 0;
	n = NULL;

	if (sc_fd < 0) {
		status = sc_init();
		if (status < 0 )
			goto err;
	}

	/* get key size */
	sectok_apdu(sc_fd, CLA_SSH, INS_GET_KEYLENGTH, 0, 0, 0, NULL,
	    sizeof(buf), buf, &sw);
	if (!sectok_swOK(sw)) {
		error("could not obtain key length: %s", sectok_get_sw(sw));
		goto err;
	}
	len = (buf[0] << 8) | buf[1];
	len /= 8;
	debug("INS_GET_KEYLENGTH: len %d sw %s", len, sectok_get_sw(sw));

	n = xmalloc(len);
	/* get n */
	sectok_apdu(sc_fd, CLA_SSH, INS_GET_PUBKEY, 0, 0, 0, NULL, len, n, &sw);
	if (!sectok_swOK(sw)) {
		error("could not obtain public key: %s", sectok_get_sw(sw));
		goto err;
	}

	debug("INS_GET_KEYLENGTH: sw %s", sectok_get_sw(sw));

	if (BN_bin2bn(n, len, k->rsa->n) == NULL) {
		error("c_read_pubkey: BN_bin2bn failed");
		goto err;
	}

	/* currently the java applet just stores 'n' */
	if (!BN_set_word(k->rsa->e, 35)) {
		error("c_read_pubkey: BN_set_word(e, 35) failed");
		goto err;
	}

	status = 0;
	p = key_fingerprint(k, SSH_FP_MD5, SSH_FP_HEX);
	debug("fingerprint %d %s", key_size(k), p);
	xfree(p);

err:
	if (n != NULL)
		xfree(n);
	sc_close();
	return status;
}

/* private key operations */

static int
sc_private_decrypt(int flen, u_char *from, u_char *to, RSA *rsa,
    int padding)
{
	u_char *padded = NULL;
	int sw, len, olen, status = -1;

	debug("sc_private_decrypt called");

	olen = len = sw = 0;
	if (sc_fd < 0) {
		status = sc_init();
		if (status < 0 )
			goto err;
	}
	if (padding != RSA_PKCS1_PADDING)
		goto err;

	len = BN_num_bytes(rsa->n);
	padded = xmalloc(len);

	sectok_apdu(sc_fd, CLA_SSH, INS_DECRYPT, 0, 0, len, (u_char *)from,
	    0, NULL, &sw);
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
	sc_close();
	return (olen >= 0 ? olen : status);
}

static int
sc_private_encrypt(int flen, u_char *from, u_char *to, RSA *rsa,
    int padding)
{
	u_char *padded = NULL;
	int sw, len, status = -1;

	len = sw = 0;
	if (sc_fd < 0) {
		status = sc_init();
		if (status < 0 )
			goto err;
	}
	if (padding != RSA_PKCS1_PADDING)
		goto err;

	debug("sc_private_encrypt called");
	len = BN_num_bytes(rsa->n);
	padded = xmalloc(len);

	if (RSA_padding_add_PKCS1_type_1(padded, len, (u_char *)from, flen) <= 0) {
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
	sc_close();
	return (len >= 0 ? len : status);
}

/* called on free */

static int (*orig_finish)(RSA *rsa) = NULL;

static int
sc_finish(RSA *rsa)
{
	if (orig_finish)
		orig_finish(rsa);
	sc_close();
	return 1;
}


/* engine for overloading private key operations */

static ENGINE *smart_engine = NULL;
static RSA_METHOD smart_rsa;

ENGINE *
sc_get_engine(void)
{
	const RSA_METHOD *def;

	def = RSA_get_default_openssl_method();

	/* use the OpenSSL version */
	memcpy(&smart_rsa, def, sizeof(smart_rsa));

	smart_rsa.name		= "sectok";

	/* overload */
	smart_rsa.rsa_priv_enc	= sc_private_encrypt;
	smart_rsa.rsa_priv_dec	= sc_private_decrypt;

	/* save original */
	orig_finish		= def->finish;
	smart_rsa.finish	= sc_finish;

	if ((smart_engine = ENGINE_new()) == NULL)
		fatal("ENGINE_new failed");

	ENGINE_set_id(smart_engine, "sectok");
	ENGINE_set_name(smart_engine, "libsectok");

	ENGINE_set_RSA(smart_engine, &smart_rsa);
	ENGINE_set_DSA(smart_engine, DSA_get_default_openssl_method());
	ENGINE_set_DH(smart_engine, DH_get_default_openssl_method());
	ENGINE_set_RAND(smart_engine, RAND_SSLeay());
	ENGINE_set_BN_mod_exp(smart_engine, BN_mod_exp);

	return smart_engine;
}

void
sc_close(void)
{
	if (sc_fd >= 0) {
		sectok_close(sc_fd);
		sc_fd = -1;
	}
}

Key *
sc_get_key(const char *id)
{
	Key *k;
	int status;

	if (sc_reader_id != NULL)
		xfree(sc_reader_id);
	sc_reader_id = xstrdup(id);

	k = key_new(KEY_RSA);
	if (k == NULL) {
		return NULL;
	}
	status = sc_read_pubkey(k);
	if (status == SCARD_ERROR_NOCARD) {
		key_free(k);
		return NULL;
	}
	if (status < 0 ) {
		error("sc_read_pubkey failed");
		key_free(k);
		return NULL;
	}
	return k;
}

#define NUM_RSA_KEY_ELEMENTS 5+1
#define COPY_RSA_KEY(x, i) \
	do { \
		len = BN_num_bytes(prv->rsa->x); \
		elements[i] = xmalloc(len); \
		debug("#bytes %d", len); \
		if (BN_bn2bin(prv->rsa->x, elements[i]) < 0) \
			goto done; \
	} while (0)

static int
get_AUT0(char *aut0)
{
	const EVP_MD *evp_md = EVP_sha1();
	EVP_MD_CTX md;
	char *pass;

	pass = read_passphrase("Enter passphrase for smartcard: ", RP_ALLOW_STDIN);
	if (pass == NULL)
		return -1;
	EVP_DigestInit(&md, evp_md);
	EVP_DigestUpdate(&md, pass, strlen(pass));
	EVP_DigestFinal(&md, aut0, NULL);
	memset(pass, 0, strlen(pass));
	xfree(pass);
	return 0;
}

int
sc_put_key(Key *prv, const char *id)
{
	u_char *elements[NUM_RSA_KEY_ELEMENTS];
	u_char key_fid[2];
	u_char DEFAUT0[] = {0xad, 0x9f, 0x61, 0xfe, 0xfa, 0x20, 0xce, 0x63};
	u_char AUT0[EVP_MAX_MD_SIZE];
	int len, status = -1, i, fd = -1, ret;
	int sw = 0, cla = 0x00;

	for (i = 0; i < NUM_RSA_KEY_ELEMENTS; i++)
		elements[i] = NULL;

	COPY_RSA_KEY(q, 0);
	COPY_RSA_KEY(p, 1);
	COPY_RSA_KEY(iqmp, 2);
	COPY_RSA_KEY(dmq1, 3);
	COPY_RSA_KEY(dmp1, 4);
	COPY_RSA_KEY(n, 5);
	len = BN_num_bytes(prv->rsa->n);
	fd = sectok_friendly_open(sc_reader_id, STONOWAIT, &sw);
	if (fd < 0) {
		error("sectok_open failed: %s", sectok_get_sw(sw));
		goto done;
	}
	if (! sectok_cardpresent(fd)) {
		error("smartcard in reader %s not present",
		    sc_reader_id);
		goto done;
	}
	ret = sectok_reset(fd, 0, NULL, &sw);
	if (ret <= 0) {
		error("sectok_reset failed: %s", sectok_get_sw(sw));
		goto done;
	}
	if ((cla = cyberflex_inq_class(fd)) < 0) {
		error("cyberflex_inq_class failed");
		goto done;
	}
	memcpy(AUT0, DEFAUT0, sizeof(DEFAUT0));
	if (cyberflex_verify_AUT0(fd, cla, AUT0, sizeof(DEFAUT0)) < 0) {
		if (get_AUT0(AUT0) < 0 ||
		    cyberflex_verify_AUT0(fd, cla, AUT0, sizeof(DEFAUT0)) < 0) {
			error("cyberflex_verify_AUT0 failed");
			goto done;
		}
	}
	key_fid[0] = 0x00;
	key_fid[1] = 0x12;
	if (cyberflex_load_rsa_priv(fd, cla, key_fid, 5, 8*len, elements,
	    &sw) < 0) {
		error("cyberflex_load_rsa_priv failed: %s", sectok_get_sw(sw));
		goto done;
	}
	if (!sectok_swOK(sw))
		goto done;
	log("cyberflex_load_rsa_priv done");
	key_fid[0] = 0x73;
	key_fid[1] = 0x68;
	if (cyberflex_load_rsa_pub(fd, cla, key_fid, len, elements[5],
	    &sw) < 0) {
		error("cyberflex_load_rsa_pub failed: %s", sectok_get_sw(sw));
		goto done;
	}
	if (!sectok_swOK(sw))
		goto done;
	log("cyberflex_load_rsa_pub done");
	status = 0;

done:
	memset(elements[0], '\0', BN_num_bytes(prv->rsa->q));
	memset(elements[1], '\0', BN_num_bytes(prv->rsa->p));
	memset(elements[2], '\0', BN_num_bytes(prv->rsa->iqmp));
	memset(elements[3], '\0', BN_num_bytes(prv->rsa->dmq1));
	memset(elements[4], '\0', BN_num_bytes(prv->rsa->dmp1));
	memset(elements[5], '\0', BN_num_bytes(prv->rsa->n));

	for (i = 0; i < NUM_RSA_KEY_ELEMENTS; i++)
		if (elements[i])
			xfree(elements[i]);
	if (fd != -1)
		sectok_close(fd);
	return (status);
}
#endif /* SMARTCARD */
