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

#include "includes.h"
#include <openssl/rand.h>
#include <openssl/rc4.h>

#ifndef HAVE_ARC4RANDOM

/* Size of key to use */
#define SEED_SIZE 20

/* Number of bytes to reseed after */
#define REKEY_BYTES	(1 << 18)

static int rc4_ready = 0;
static RC4_KEY rc4;

unsigned int arc4random(void)
{
	unsigned int r = 0;

	if (rc4_ready <= 0)
		arc4random_stir();
	
	RC4(&rc4, sizeof(r), (unsigned char *)&r, (unsigned char *)&r);

	rc4_ready -= sizeof(r);
	
	return(r);
}

void arc4random_stir(void)
{
	unsigned char rand_buf[SEED_SIZE];
	
	memset(&rc4, 0, sizeof(rc4));

	seed_rng();

	RAND_bytes(rand_buf, sizeof(rand_buf));
	
	RC4_set_key(&rc4, sizeof(rand_buf), rand_buf);

	memset(rand_buf, 0, sizeof(rand_buf));
	
	rc4_ready = REKEY_BYTES;
}
#endif /* !HAVE_ARC4RANDOM */
