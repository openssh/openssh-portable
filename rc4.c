/*! \file rc4.c
    \brief Source file for RC4 stream cipher routines
	 \author Damien Miller <djm@mindrot.org>
	 \version 0.0.0
	 \date 1999
	 
	 A simple implementation of the RC4 stream cipher, based on the
	 description given in _Bruce Schneier's_ "Applied Cryptography"
	 2nd edition.

	 Copyright 1999 Damien Miller

	 Permission is hereby granted, free of charge, to any person
	 obtaining a copy of this software and associated documentation
	 files (the "Software"), to deal in the Software without
	 restriction, including without limitation the rights to use, copy,
	 modify, merge, publish, distribute, sublicense, and/or sell copies
	 of the Software, and to permit persons to whom the Software is
	 furnished to do so, subject to the following conditions:

	 The above copyright notice and this permission notice shall be
	 included in all copies or substantial portions of the Software.

	 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
	 KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
	 WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
	 AND NONINFRINGEMENT.  IN NO EVENT SHALL DAMIEN MILLER BE LIABLE
	 FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
	 CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
	 WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

	 \warning None of these functions clears its memory after use. It
	 \warning is the responsability of the calling routines to ensure
	 \warning that any sensitive data (keystream, key or plaintext) is
	 \warning properly erased after use.
	 
	 \warning The name "RC4" is trademarked in the United States, 
	 \warning you may need to use "RC4 compatible" or "ARC4" 
	 \warning (Alleged RC4).
*/

/* $Id: rc4.c,v 1.1.1.1 1999/10/26 05:48:13 damien Exp $ */

#include "rc4.h"


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

void rc4_crypt(rc4_t *r, unsigned char *plaintext, int len)
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

		plaintext[c] ^= r->s[t];
		c++;
	}
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
