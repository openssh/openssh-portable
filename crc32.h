/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1992 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for computing 32-bit CRC.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/* RCSID("$OpenBSD: crc32.h,v 1.12 2001/06/26 17:27:23 markus Exp $"); */

#ifndef CRC32_H
#define CRC32_H

u_int	 ssh_crc32(const u_char *, u_int);

#endif				/* CRC32_H */
