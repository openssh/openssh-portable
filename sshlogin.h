/*	$OpenBSD: sshlogin.h,v 1.2 2001/06/26 06:33:04 itojun Exp $	*/

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
#ifndef SSHLOGIN_H
#define SSHLOGIN_H

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host from which the user logged in is stored in buf.
 */
u_long
get_last_login_time(uid_t, const char *, char *, u_int);

/*
 * Records that the user has logged in.  This does many things normally done
 * by login(1).
 */
void
record_login(pid_t, const char *, const char *, uid_t, const char *,
		struct sockaddr *);

#ifdef LOGIN_NEEDS_UTMPX
/*
 * Record just the utmp info for /bin/login.
 */
void
record_utmp_only(pid_t, const char *, const char *, const char *, 
		struct sockaddr *);
#endif

/*
 * Records that the user has logged out.  This does many thigs normally done
 * by login(1) or init.
 */
void    record_logout(pid_t, const char *);

#endif
