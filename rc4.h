/*! \file rc4.h
    \brief Header file for RC4 stream cipher routines
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

/* $Id: rc4.h,v 1.1.1.1 1999/10/26 05:48:13 damien Exp $ */

#ifndef _RC4_H
#define _RC4_H

/*! \struct rc4_t
    \brief RC4 stream cipher state object
	 \var s State array
	 \var i Monotonic index
	 \var j Randomised index
	 
	 \warning This structure should not be accessed directly. To
	 \warning initialise a rc4_t object, you should use the rc4_key()
	 \warning function
	 
	 This structure holds the current state of the RC4 algorithm.
*/
typedef struct
{
	unsigned int s[256];
	int i;
	int j;
} rc4_t;

/*! \fn void rc4_key(rc4_t *r, unsigned char *key, int len);
    \brief Set up key structure of RC4 stream cipher
	 \param r pointer to RC4 structure to be seeded
	 \param key pointer to buffer containing raw key
	 \param len length of key
	 
	 This function set the internal state of the RC4 data structure
	 pointed to by \a r using the specified \a key of length \a len.
	 
	 This function can use up to 256 bytes of key, any more are ignored.
	 
	 \warning Stream ciphers (such as RC4) can be insecure if the same
	 \warning key is used repeatedly. Ensure that any key specified has
	 \warning an reasonably sized Initialisation Vector component.
*/
void rc4_key(rc4_t *r, unsigned char *key, int len);

/*! \fn rc4_crypt(rc4_t *r, unsigned char *plaintext, int len);
    \brief Crypt bytes using RC4 algorithm
	 \param r pointer to RC4 structure to be used
	 \param plaintext Pointer to bytes to encrypt
	 \param len number of bytes to crypt

	 This function encrypts one or more bytes (pointed to by \a plaintext)
	 using the RC4 algorithm. \a r is a state structure that must be 
	 initialiased using the rc4_key() function prior to use.
	 
	 Since RC4 XORs each byte of plaintext with a byte of keystream,
	 this function can be used for both encryption and decryption.
*/
void rc4_crypt(rc4_t *r, unsigned char *plaintext, int len);

/*! \fn rc4_getbytes(rc4_t *r, unsigned char *buffer, int len);
    \brief Generate key stream using the RC4 stream cipher
	 \param r pointer to RC4 structure to be used
	 \param buffer pointer to buffer in which to deposit keystream
	 \param len number of bytes to deposit

	 This function gives access to the raw RC4 key stream. In this 
	 consiguration RC4 can be used as a fast, strong pseudo-random 
	 number generator with a very long period.
*/
void rc4_getbytes(rc4_t *r, unsigned char *buffer, int len);

#endif /* _RC4_H */
