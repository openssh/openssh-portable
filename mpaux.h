/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains various auxiliary functions related to multiple
 * precision integers.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/* RCSID("$OpenBSD: mpaux.h,v 1.10 2001/06/26 06:32:57 itojun Exp $"); */

#ifndef MPAUX_H
#define MPAUX_H

/*
 * Computes a 16-byte session id in the global variable session_id. The
 * session id is computed by concatenating the linearized, msb first
 * representations of host_key_n, session_key_n, and the cookie.
 */
void
compute_session_id(u_char[16], u_char[8], BIGNUM *, BIGNUM *);

#endif				/* MPAUX_H */
