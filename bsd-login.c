/*
 * This file has been modified from the original OpenBSD version 
 */

/*	$OpenBSD: login.c,v 1.5 1998/07/13 02:11:12 millert Exp $	*/
/*
 * Copyright (c) 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"
#ifndef HAVE_LOGIN

#include <errno.h>

#if defined(LIBC_SCCS) && !defined(lint)
/* from: static char sccsid[] = "@(#)login.c	8.1 (Berkeley) 6/4/93"; */
static char *rcsid = "$OpenBSD: login.c,v 1.5 1998/07/13 02:11:12 millert Exp $";
#endif /* LIBC_SCCS and not lint */

#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#if defined(HAVE_UTMPX_H) && defined(USE_UTMPX)
# include <utmpx.h>
#endif
#ifdef HAVE_UTMP_H
# include <utmp.h>
#endif
#include <stdio.h>
#include <string.h>

/*
 * find first matching slot in utmp, or "-1" for none
 *
 * algorithm: for USER_PROCESS, check tty name
 *            for DEAD_PROCESS, check PID and tty name
 *
 */
int find_tty_slot( utp )
struct utmp * utp;
{
	int t = 0;
	struct utmp * u;

	setutent();

	while((u = getutent()) != NULL) {
		if (utp->ut_type == USER_PROCESS &&
		    (strncmp(utp->ut_line, u->ut_line, sizeof(utp->ut_line)) == 0)) {
			endutent();
			return(t);
		}

		if ((utp->ut_type == DEAD_PROCESS) && (utp->ut_pid == u->ut_pid) &&
		    (strncmp(utp->ut_line, u->ut_line, sizeof(utp->ut_line)) == 0 )) {
			endutent();
			return(t);
		}
		t++;
	}

	endutent();
	return(-1);
}

#if defined(HAVE_UTMPX_H) && defined(USE_UTMPX)
void
login(utp,utx)
	struct utmp *utp;
	struct utmpx *utx;
#else /* defined(HAVE_UTMPX_H) && defined(USE_UTMPX) */
void
login(utp)
	struct utmp *utp;
#endif /* defined(HAVE_UTMPX_H) && defined(USE_UTMPX) */
{
#if defined(HAVE_HOST_IN_UTMP)
	struct utmp old_ut;
#endif
#if defined(HAVE_UTMPX_H) && defined(USE_UTMPX)
	struct utmpx *old_utx;
#endif /* defined(HAVE_UTMPX_H) && defined(USE_UTMPX) */
	register int fd;
	int tty;

	/* can't use ttyslot here, as that will not work for logout
	 * (record_logout() is called from the master sshd, which does
	 * not have the correct tty on stdin/out, so ttyslot will return
	 * "-1" or (worse) a wrong number
	 */
	tty = find_tty_slot(utp);

	fd = open(_PATH_UTMP, O_RDWR|O_CREAT, 0644);
	if (fd == -1) {
		log("Couldn't open %s: %s", _PATH_UTMP, strerror(errno));
	} else {
		/* If no tty was found... */
		if (tty == -1) {
			/* ... append it to utmp on login */
			if (utp->ut_type == USER_PROCESS) {
				if ((fd = open(_PATH_UTMP, O_WRONLY|O_APPEND, 0)) >= 0) {
					(void)write(fd, utp, sizeof(struct utmp));
					(void)close(fd);
				}
			} else {
				/* Shouldn't get to here unless somthing happened to utmp */
				/* Between login and logout */
				log("No tty slot found at logout");
			}
		} else {
			/* Otherwise, tty was found - update at its location */
#if defined(HAVE_HOST_IN_UTMP)
# ifndef UT_LINESIZE
#  define UT_LINESIZE (sizeof(old_ut.ut_line))
#  define UT_NAMESIZE (sizeof(old_ut.ut_name))
#  define UT_HOSTSIZE (sizeof(old_ut.ut_host))
# endif
			(void)lseek(fd, (off_t)(tty * sizeof(struct utmp)), SEEK_SET);
			/*
			 * Prevent luser from zero'ing out ut_host.
			 * If the new ut_line is empty but the old one is not
			 * and ut_line and ut_name match, preserve the old ut_line.
			 */
			if (read(fd, &old_ut, sizeof(struct utmp)) ==
		   	 sizeof(struct utmp) && utp->ut_host[0] == '\0' &&
		   	 old_ut.ut_host[0] != '\0' &&
		   	 strncmp(old_ut.ut_line, utp->ut_line, UT_LINESIZE) == 0 &&
		   	 strncmp(old_ut.ut_name, utp->ut_name, UT_NAMESIZE) == 0)
				(void)memcpy(utp->ut_host, old_ut.ut_host, UT_HOSTSIZE);
#endif /* defined(HAVE_HOST_IN_UTMP) */
			(void)lseek(fd, (off_t)(tty * sizeof(struct utmp)), SEEK_SET);
			(void)write(fd, utp, sizeof(struct utmp));
			(void)close(fd);
		}
	}

	if ((fd = open(_PATH_WTMP, O_WRONLY|O_APPEND, 0)) >= 0) {
		(void)write(fd, utp, sizeof(struct utmp));
		(void)close(fd);
	}
#if defined(HAVE_UTMPX_H) && defined(USE_UTMPX)
	old_utx = pututxline(utx);
# ifdef HAVE_UPDWTMPX
	updwtmpx(_PATH_WTMPX, utx);
# endif /* HAVE_UPDWTMPX */
	endutxent();
#endif /* defined(HAVE_UTMPX_H) && defined(USE_UTMPX) */
}

#endif /* HAVE_LOGIN */
