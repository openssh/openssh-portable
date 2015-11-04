/* $OpenBSD: bufec.c,v 1.3 2014/01/31 16:39:19 tedu Exp $ */
/*
 * Copyright (c) 2010 Damien Miller <djm@mindrot.org>
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

#ifdef OPENSSL_HAS_ECC

#include <sys/types.h>

#ifdef USING_WOLFSSL
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/ec.h>
#else
#include <openssl/bn.h>
#include <openssl/ec.h>
#endif

#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "buffer.h"
#include "log.h"
#include "misc.h"

/*
 * Maximum supported EC GFp field length is 528 bits. SEC1 uncompressed
 * encoding represents this as two bitstring points that should each
 * be no longer than the field length, SEC1 specifies a 1 byte
 * point type header.
 * Being paranoid here may insulate us to parsing problems in
 * EC_POINT_oct2point.
 */
#define BUFFER_MAX_ECPOINT_LEN ((528*2 / 8) + 1)

/*
 * Append an EC_POINT to the buffer as a string containing a SEC1 encoded
 * uncompressed point. Fortunately OpenSSL handles the gory details for us.
 */
int
buffer_put_ecpoint_ret(Buffer *buffer, const EC_GROUP *curve,
    const EC_POINT *point)
{
	u_char *buf = NULL;
#ifndef USING_WOLFSSL
	BN_CTX *bnctx;
	size_t len;
#else
	int err;
	unsigned int len;
#endif
	int ret = -1;

	/* Determine length */
#ifndef USING_WOLFSSL
	if ((bnctx = BN_CTX_new()) == NULL)
		fatal("%s: BN_CTX_new failed", __func__);
	len = EC_POINT_point2oct(curve, point, POINT_CONVERSION_UNCOMPRESSED,
	    NULL, 0, bnctx);
	if (len > BUFFER_MAX_ECPOINT_LEN) {
		error("%s: giant EC point: len = %lu (max %u)",
		    __func__, (u_long)len, BUFFER_MAX_ECPOINT_LEN);
		goto out;
	}
#else
	err = wolfSSL_ECPoint_i2d(curve, point, NULL, &len);
	if (err != 1 || len <= 0 || len > BUFFER_MAX_ECPOINT_LEN) {
		error("%s: giant EC point (%d): len = %lu (max %u)",
			  __func__, err, (u_long)len, BUFFER_MAX_ECPOINT_LEN);
		goto out;
	}

#endif /* USING_WOLFSSL */

	/* Convert */
	buf = xmalloc(len);

#ifndef USING_WOLFSSL
	if (EC_POINT_point2oct(curve, point, POINT_CONVERSION_UNCOMPRESSED,
	    buf, len, bnctx) != len) {
		error("%s: EC_POINT_point2oct length mismatch", __func__);
		goto out;
	}
#else
	err = wolfSSL_ECPoint_i2d(curve, point, buf, &len);
	if (err != 1) {
		error("%s: wolfSSL_ECPoint_i2d failed", __func__);
		goto out;
	}
#endif /* USING_WOLFSSL */

	/* Append */
	buffer_put_string(buffer, buf, len);
	ret = 0;
 out:
	if (buf != NULL) {
		explicit_bzero(buf, len);
		free(buf);
	}
#ifndef USING_WOLFSSL
	BN_CTX_free(bnctx);
#endif
	return ret;
}

void
buffer_put_ecpoint(Buffer *buffer, const EC_GROUP *curve,
    const EC_POINT *point)
{
	if (buffer_put_ecpoint_ret(buffer, curve, point) == -1)
		fatal("%s: buffer error", __func__);
}

int
buffer_get_ecpoint_ret(Buffer *buffer, const EC_GROUP *curve,
    EC_POINT *point)
{
	u_char *buf;
	u_int len;
#ifndef USING_WOLFSSL
	BN_CTX *bnctx;
#endif
	int ret = -1;

	if ((buf = buffer_get_string_ret(buffer, &len)) == NULL) {
		error("%s: invalid point", __func__);
		return -1;
	}
#ifndef USING_WOLFSSL
	if ((bnctx = BN_CTX_new()) == NULL)
		fatal("%s: BN_CTX_new failed", __func__);
#endif
	if (len > BUFFER_MAX_ECPOINT_LEN) {
		error("%s: EC_POINT too long: %u > max %u", __func__,
		    len, BUFFER_MAX_ECPOINT_LEN);
		goto out;
	}
	if (len == 0) {
		error("%s: EC_POINT buffer is empty", __func__);
		goto out;
	}
	if (buf[0] != POINT_CONVERSION_UNCOMPRESSED) {
		error("%s: EC_POINT is in an incorrect form: "
		    "0x%02x (want 0x%02x)", __func__, buf[0],
		    POINT_CONVERSION_UNCOMPRESSED);
		goto out;
	}
#ifndef USING_WOLFSSL
	if (EC_POINT_oct2point(curve, point, buf, len, bnctx) != 1) {
		error("buffer_get_bignum2_ret: BN_bin2bn failed");
#else
	if (wolfSSL_ECPoint_d2i(buf, len, curve, point) != 1) {
		error("wolfSSL_ECPoint_d2i failed");
#endif
		goto out;
	}
	/* EC_POINT_oct2point verifies that the point is on the curve for us */
	ret = 0;
 out:
#ifndef USING_WOLFSSL
	BN_CTX_free(bnctx);
#endif
	explicit_bzero(buf, len);
	free(buf);
	return ret;
}

void
buffer_get_ecpoint(Buffer *buffer, const EC_GROUP *curve,
    EC_POINT *point)
{
	if (buffer_get_ecpoint_ret(buffer, curve, point) == -1)
		fatal("%s: buffer error", __func__);
}

#endif /* OPENSSL_HAS_ECC */
