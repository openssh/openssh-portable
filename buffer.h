/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Code for manipulating FIFO buffers.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/* RCSID("$OpenBSD: buffer.h,v 1.9 2001/06/26 17:27:23 markus Exp $"); */

#ifndef BUFFER_H
#define BUFFER_H

typedef struct {
	char	*buf;		/* Buffer for data. */
	u_int	 alloc;		/* Number of bytes allocated for data. */
	u_int	 offset;	/* Offset of first byte containing data. */
	u_int	 end;		/* Offset of last byte containing data. */
}       Buffer;

void	 buffer_init(Buffer *);
void	 buffer_clear(Buffer *);
void	 buffer_free(Buffer *);

u_int	 buffer_len(Buffer *);
char	*buffer_ptr(Buffer *);

void	 buffer_append(Buffer *, const char *, u_int);
void	 buffer_append_space(Buffer *, char **, u_int);

void	 buffer_get(Buffer *, char *, u_int);

void	 buffer_consume(Buffer *, u_int);
void	 buffer_consume_end(Buffer *, u_int);

void     buffer_dump(Buffer *);

#endif				/* BUFFER_H */
