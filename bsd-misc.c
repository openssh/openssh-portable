/*
 * Copyright (c) 1999-2000 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Markus Friedl.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "bsd-misc.h"
#include "entropy.h"

#include <openssl/rand.h>

#ifndef HAVE_ARC4RANDOM

typedef struct
{
	unsigned int s[256];
	int i;
	int j;
} rc4_t;

void rc4_key(rc4_t *r, unsigned char *key, int len);
void rc4_getbytes(rc4_t *r, unsigned char *buffer, int len);

static rc4_t *rc4 = NULL;

void rc4_key(rc4_t *r, unsigned char *key, int len)
{
	int t;
	
	for(r->i = 0; r->i < 256; r->i++)
		r->s[r->i] = r->i;

	r->j = 0;
	for(r->i = 0; r->i < 256; r->i++)
	{
		r->j = (r->j + r->s[r->i] + key[r->i % len]) % 256;
		t = r->s[r->i];
		r->s[r->i] = r->s[r->j];
		r->s[r->j] = t;
	}
	r->i = r->j = 0;
}

void rc4_getbytes(rc4_t *r, unsigned char *buffer, int len)
{
	int t;
	int c;

	c = 0;	
	while(c < len)
	{
		r->i = (r->i + 1) % 256;
		r->j = (r->j + r->s[r->i]) % 256;
		t = r->s[r->i];
		r->s[r->i] = r->s[r->j];
		r->s[r->j] = t;

		t = (r->s[r->i] + r->s[r->j]) % 256;
		
		buffer[c] = r->s[t];
		c++;
	}
}

unsigned int arc4random(void)
{
	unsigned int r;

	if (rc4 == NULL)
		arc4random_stir();
	
	rc4_getbytes(rc4, (unsigned char *)&r, sizeof(r));
	
	return(r);
}

void arc4random_stir(void)
{
	unsigned char rand_buf[32];
	
	if (rc4 == NULL)
		rc4 = xmalloc(sizeof(*rc4));

	seed_rng();
	RAND_bytes(rand_buf, sizeof(rand_buf));
	
	rc4_key(rc4, rand_buf, sizeof(rand_buf));
	memset(rand_buf, 0, sizeof(rand_buf));
}
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_SETPROCTITLE
void setproctitle(const char *fmt, ...)
{
	/* FIXME */
}
#endif /* !HAVE_SETPROCTITLE */

#ifndef HAVE_SETLOGIN
int setlogin(const char *name)
{
	return(0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
int innetgr(const char *netgroup, const char *host, 
            const char *user, const char *domain)
{
	return(0);
}
#endif /* HAVE_INNETGR */

#if !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
int seteuid(uid_t euid)
{
	return(setreuid(-1,euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#if !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST)
const char *strerror(void)
{
	return(sys_errlist[errno]);
}
#endif /* !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) */
