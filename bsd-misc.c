/*
**
** OpenBSD replacement routines
**
** Damien Miller <djm@ibs.com.au>
** 
** Copyright 1999 Damien Miller
** Copyright 1999 Internet Business Solutions
**
** Permission is hereby granted, free of charge, to any person
** obtaining a copy of this software and associated documentation
** files (the "Software"), to deal in the Software without
** restriction, including without limitation the rights to use, copy,
** modify, merge, publish, distribute, sublicense, and/or sell copies
** of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
**
** The above copyright notice and this permission notice shall be
** included in all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
** KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
** WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
** AND NONINFRINGEMENT.  IN NO EVENT SHALL DAMIEN MILLER OR INTERNET
** BUSINESS SOLUTIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
** ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
** OR OTHER DEALINGS IN THE SOFTWARE.
**
** Except as contained in this notice, the name of Internet Business
** Solutions shall not be used in advertising or otherwise to promote
** the sale, use or other dealings in this Software without prior
** written authorization from Internet Business Solutions.
**
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
#include "random.h"

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
	
	get_random_bytes(rand_buf, sizeof(rand_buf));
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
