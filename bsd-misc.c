/*
**
** OpenBSD emulation routines
**
** Damien Miller <djm@ibs.com.au>
** 
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#include "xmalloc.h"
#include "ssh.h"
#include "config.h"
#include "bsd-misc.h"

#ifndef offsetof
#define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

#ifndef HAVE_ARC4RANDOM

typedef struct
{
	unsigned int s[256];
	int i;
	int j;
} rc4_t;

void get_random_bytes(unsigned char *buf, int len);
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
}

void get_random_bytes(unsigned char *buf, int len)
{
	static int random_pool;
	int c;
#ifdef HAVE_EGD
	char egd_message[2] = { 0x02, 0x00 };
	struct sockaddr_un addr;
	int addr_len;

	memset(&addr, '\0', sizeof(addr));
	addr.sun_family = AF_UNIX;
	
	/* FIXME: compile time check? */
	if (sizeof(RANDOM_POOL) > sizeof(addr.sun_path))
		fatal("Random pool path is too long");
	
	strcpy(addr.sun_path, RANDOM_POOL);
	
	addr_len = offsetof(struct sockaddr_un, sun_path) + sizeof(RANDOM_POOL);
	
	random_pool = socket(AF_UNIX, SOCK_STREAM, 0);
	
	if (random_pool == -1)
		fatal("Couldn't create AF_UNIX socket: %s", strerror(errno));
	
	if (connect(random_pool, (struct sockaddr*)&addr, addr_len) == -1)
		fatal("Couldn't connect to EGD socket \"%s\": %s", addr.sun_path, strerror(errno));

	if (len > 255)
		fatal("Too many bytes to read from EGD");
	
	/* Send blocking read request to EGD */
	egd_message[1] = len;

	c = atomicio(write, random_pool, egd_message, sizeof(egd_message));
	if (c == -1)
		fatal("Couldn't write to EGD socket \"%s\": %s", RANDOM_POOL, strerror(errno));

#else /* HAVE_EGD */

	random_pool = open(RANDOM_POOL, O_RDONLY);
	if (random_pool == -1)
		fatal("Couldn't open random pool \"%s\": %s", RANDOM_POOL, strerror(errno));

#endif /* HAVE_EGD */

	c = atomicio(read, random_pool, buf, len);
	if (c <= 0)
		fatal("Couldn't read from random pool \"%s\": %s", RANDOM_POOL, strerror(errno));
	
	close(random_pool);
}
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_SETPROCTITLE
void setproctitle(const char *fmt, ...)
{
	/* FIXME */
}
#endif /* !HAVE_SETPROCTITLE */

#ifndef HAVE_SETENV
int setenv(const char *name, const char *value, int overwrite)
{
	char *env_string;
	int result;
	
	/* Don't overwrite existing env. var if overwrite is 0 */
	if (!overwrite && (getenv(name) != NULL))
		return(0);
	
	env_string = xmalloc(strlen(name) + strlen(value) + 2);
	sprintf(env_string, "%s=%s", name, value);
	
	result = putenv(env_string);
	
	xfree(env_string);
	
	return(result);	
}
#endif /* !HAVE_SETENV */
