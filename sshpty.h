/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for allocating a pseudo-terminal and making it the controlling
 * tty.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/* RCSID("$OpenBSD: sshpty.h,v 1.2 2001/06/26 06:33:04 itojun Exp $"); */

#ifndef SSHPTY_H
#define SSHPTY_H

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */
int     pty_allocate(int *, int *, char *, int);

/*
 * Releases the tty.  Its ownership is returned to root, and permissions to
 * 0666.
 */
void    pty_release(const char *);

/*
 * Makes the tty the processes controlling tty and sets it to sane modes.
 * This may need to reopen the tty to get rid of possible eavesdroppers.
 */
void    pty_make_controlling_tty(int *, const char *);

/* Changes the window size associated with the pty. */
void	pty_change_window_size(int, int, int, int, int);

void	pty_setowner(struct passwd *, const char *);

#endif				/* SSHPTY_H */
