/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/* RCSID("$OpenBSD: bufaux.h,v 1.12 2001/06/26 06:32:48 itojun Exp $"); */

#ifndef BUFAUX_H
#define BUFAUX_H

#include "buffer.h"
#include <openssl/bn.h>

/*
 * Stores an BIGNUM in the buffer with a 2-byte msb first bit count, followed
 * by (bits+7)/8 bytes of binary data, msb first.
 */
void    buffer_put_bignum(Buffer *, BIGNUM *);
void    buffer_put_bignum2(Buffer *, BIGNUM *);

/* Retrieves an BIGNUM from the buffer. */
int     buffer_get_bignum(Buffer *, BIGNUM *);
int	buffer_get_bignum2(Buffer *, BIGNUM *);

/* Returns an integer from the buffer (4 bytes, msb first). */
u_int buffer_get_int(Buffer *);
#ifdef HAVE_U_INT64_T
u_int64_t buffer_get_int64(Buffer *);
#endif

/* Stores an integer in the buffer in 4 bytes, msb first. */
void    buffer_put_int(Buffer *, u_int);
#ifdef HAVE_U_INT64_T
void	buffer_put_int64(Buffer *, u_int64_t);
#endif

/* Returns a character from the buffer (0 - 255). */
int     buffer_get_char(Buffer *);

/* Stores a character in the buffer. */
void    buffer_put_char(Buffer *, int);

/*
 * Returns an arbitrary binary string from the buffer.  The string cannot be
 * longer than 256k.  The returned value points to memory allocated with
 * xmalloc; it is the responsibility of the calling function to free the
 * data.  If length_ptr is non-NULL, the length of the returned data will be
 * stored there.  A null character will be automatically appended to the
 * returned string, and is not counted in length.
 */
char   *buffer_get_string(Buffer *, u_int *);

/* Stores and arbitrary binary string in the buffer. */
void    buffer_put_string(Buffer *, const void *, u_int);
void	buffer_put_cstring(Buffer *, const char *);

#endif				/* BUFAUX_H */
