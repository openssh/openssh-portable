/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
RCSID("$OpenBSD: hmac.c,v 1.6 2001/01/21 19:05:49 markus Exp $");

#include "xmalloc.h"
#include "getput.h"
#include "log.h"

#include <openssl/hmac.h>

u_char *
hmac(
    EVP_MD *evp_md,
    u_int seqno,
    u_char *data, int datalen,
    u_char *key, int keylen)
{
	HMAC_CTX c;
	static u_char m[EVP_MAX_MD_SIZE];
	u_char b[4];

	if (key == NULL)
		fatal("hmac: no key");
	HMAC_Init(&c, key, keylen, evp_md);
	PUT_32BIT(b, seqno);
	HMAC_Update(&c, b, sizeof b);
	HMAC_Update(&c, data, datalen);
	HMAC_Final(&c, m, NULL);
	HMAC_cleanup(&c);
	return(m);
}
