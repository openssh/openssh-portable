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
#include <fcntl.h>

#include "rc4.h"
#include "xmalloc.h"
#include "config.h"
#include "helper.h"

#ifndef HAVE_ARC4RANDOM

void get_random_bytes(unsigned char *buf, int len);

static rc4_t *rc4 = NULL;

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
	int urandom;
	int c;
	
	urandom = open("/dev/urandom", O_RDONLY);
	if (urandom == -1)
	{
		fprintf(stderr, "Couldn't open /dev/urandom: %s", strerror(errno));
		exit(1);
	}
	
	c = read(urandom, buf, len);
	if (c == -1)
	{
		fprintf(stderr, "Couldn't read from /dev/urandom: %s", strerror(errno));
		exit(1);
	}

	if (c != len)
	{
		fprintf(stderr, "Short read from /dev/urandom");
		exit(1);
	}
}
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_SETPROCTITLE
void setproctitle(const char *fmt, ...)
{
	/* FIXME */
}
#endif /* !HAVE_SETPROCTITLE */
