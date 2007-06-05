/* $OpenBSD: mac.c,v 1.13 2007/06/05 06:52:37 djm Exp $ */
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

#include <sys/types.h>

#include <openssl/hmac.h>

#include <stdarg.h>
#include <string.h>
#include <signal.h>

#include "xmalloc.h"
#include "log.h"
#include "cipher.h"
#include "buffer.h"
#include "key.h"
#include "kex.h"
#include "mac.h"
#include "misc.h"

struct {
	char		*name;
	const EVP_MD *	(*mdfunc)(void);
	int		truncatebits;	/* truncate digest if != 0 */
} macs[] = {
	{ "hmac-sha1",			EVP_sha1, 0, },
	{ "hmac-sha1-96",		EVP_sha1, 96 },
	{ "hmac-md5",			EVP_md5, 0 },
	{ "hmac-md5-96",		EVP_md5, 96 },
	{ "hmac-ripemd160",		EVP_ripemd160, 0 },
	{ "hmac-ripemd160@openssh.com",	EVP_ripemd160, 0 },
	{ NULL,				NULL, 0 }
};

int
mac_setup(Mac *mac, char *name)
{
	int i, evp_len;

	for (i = 0; macs[i].name; i++) {
		if (strcmp(name, macs[i].name) == 0) {
			if (mac != NULL) {
				mac->md = (*macs[i].mdfunc)();
				if ((evp_len = EVP_MD_size(mac->md)) <= 0)
					fatal("mac %s len %d", name, evp_len);
				mac->key_len = mac->mac_len = (u_int)evp_len;
				if (macs[i].truncatebits != 0)
					mac->mac_len = macs[i].truncatebits/8;
			}
			debug2("mac_setup: found %s", name);
			return (0);
		}
	}
	debug2("mac_setup: unknown %s", name);
	return (-1);
}

void
mac_init(Mac *mac)
{
	if (mac->key == NULL)
		fatal("mac_init: no key");
	HMAC_Init(&mac->ctx, mac->key, mac->key_len, mac->md);
}

u_char *
mac_compute(Mac *mac, u_int32_t seqno, u_char *data, int datalen)
{
	static u_char m[EVP_MAX_MD_SIZE];
	u_char b[4];

	if (mac->mac_len > sizeof(m))
		fatal("mac_compute: mac too long");
	put_u32(b, seqno);
	HMAC_Init(&mac->ctx, NULL, 0, NULL);	/* reset HMAC context */
	HMAC_Update(&mac->ctx, b, sizeof(b));
	HMAC_Update(&mac->ctx, data, datalen);
	HMAC_Final(&mac->ctx, m, NULL);
	return (m);
}

void
mac_clear(Mac *mac)
{
	HMAC_cleanup(&mac->ctx);
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
int
mac_valid(const char *names)
{
	char *maclist, *cp, *p;

	if (names == NULL || strcmp(names, "") == 0)
		return (0);
	maclist = cp = xstrdup(names);
	for ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		if (mac_setup(NULL, p) < 0) {
			debug("bad mac %s [%s]", p, names);
			xfree(maclist);
			return (0);
		} else {
			debug3("mac ok: %s [%s]", p, names);
		}
	}
	debug3("macs ok: [%s]", names);
	xfree(maclist);
	return (1);
}
