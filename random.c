/*
**
** Random number collection
**
** Damien Miller <djm@ibs.com.au>
** 
** Copyright 1999 Damien Miller
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
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#include "ssh.h"
#include "xmalloc.h"
#include "random.h"

#ifndef offsetof
# define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

#ifdef HAVE_EGD

/* Collect entropy from EGD */
void get_random_bytes(unsigned char *buf, int len)
{
	static int random_pool;
	int c;
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

	c = atomicio(read, random_pool, buf, len);
	if (c <= 0)
		fatal("Couldn't read from random pool \"%s\": %s", RANDOM_POOL, strerror(errno));
	
	close(random_pool);
}
#else /* HAVE_EGD */

/* Collect entropy from /dev/urandom or pipe */
void get_random_bytes(unsigned char *buf, int len)
{
	static int random_pool;
	int c;

	random_pool = open(RANDOM_POOL, O_RDONLY);
	if (random_pool == -1)
		fatal("Couldn't open random pool \"%s\": %s", RANDOM_POOL, strerror(errno));

	c = atomicio(read, random_pool, buf, len);
	if (c <= 0)
		fatal("Couldn't read from random pool \"%s\": %s", RANDOM_POOL, strerror(errno));
	
	close(random_pool);
}

#endif /* HAVE_EGD */
