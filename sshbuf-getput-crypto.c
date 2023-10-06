/*	$OpenBSD: sshbuf-getput-crypto.c,v 1.10 2022/05/25 06:03:44 djm Exp $	*/
/*
 * Copyright (c) 2011 Damien Miller
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

#define SSHBUF_INTERNAL
#include "includes.h"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#include "ssherr.h"
#include "sshbuf.h"

int
sshbuf_get_bignum2(struct sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	const u_char *d;
	size_t len;
	int r;

	if (valp != NULL)
		*valp = NULL;
	if ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		return r;
	if (valp != NULL) {
		if ((v = BN_new()) == NULL ||
		    BN_bin2bn(d, len, v) == NULL) {
			BN_clear_free(v);
			return SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	return 0;
}

int
sshbuf_get_ec(struct sshbuf *buf, u_char **pub, size_t *publen)
{
	/* the public key is in the buffer in octet string UNCOMPRESSED
	 * format. See sshbuf_put_ec */
	return sshbuf_get_string(buf, pub, publen);
}

int
sshbuf_put_bignum2(struct sshbuf *buf, const BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	int len = BN_num_bytes(v), prepend = 0, r;

	if (len < 0 || len > SSHBUF_MAX_BIGNUM)
		return SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	if (BN_bn2bin(v, d + 1) != len)
		return SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	if (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	if ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, sizeof(d));
		return r;
	}
	explicit_bzero(d, sizeof(d));
	return 0;
}

#ifdef OPENSSL_HAS_ECC
int
sshbuf_put_ecbuf(struct sshbuf *buf, const EC_POINT *v, const EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	int ret;

	if ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    NULL, 0, NULL)) > SSHBUF_MAX_ECPOINT) {
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, NULL) != len) {
		return SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	return ret;
}

int
sshbuf_put_ec(struct sshbuf *buf, EVP_PKEY *pkey)
{
	const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);

	if (ec == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;

	return sshbuf_put_ecbuf(buf, EC_KEY_get0_public_key(ec),
	    EC_KEY_get0_group(ec));
/* FIXME beldmit */
#if 0
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	int ret;

	/* this works since openssl version of 3.0.8 */
	if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
	    				    d, SSHBUF_MAX_ECPOINT, &len) != 1)
		return len > SSHBUF_MAX_ECPOINT ? SSH_ERR_INVALID_ARGUMENT :
						  SSH_ERR_LIBCRYPTO_ERROR;
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	return ret;
#endif
}
#endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */
