/*
 * This file has been heavily modified from the original OpenBSD version 
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

#ifdef USER_PROCESS
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

# if defined(HAVE_TYPE_IN_UTMP) || defined(HAVE_TYPE_IN_UTMPX)
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
# endif /* defined(HAVE_TYPE_IN_UTMP) || defined(HAVE_TYPE_IN_UTMPX) */
	return(-1);
}
#else /* USER_PROCESS */
int find_tty_slot(struct utmp *utp)
{
	return(ttyslot());
}
#endif /* USER_PROCESS */

#if defined(HAVE_UTMPX_H) && defined(USE_UTMPX)
void login(struct utmpx *utx)
#else /* defined(HAVE_UTMPX_H) && defined(USE_UTMPX) */
void login(struct utmp *utp)
#endif /* defined(HAVE_UTMPX_H) && defined(USE_UTMPX) */
{
	/* Use proper API if we have it */
#if defined(USE_UTMPX)
# if defined(HAVE_PUTUTXLINE)
	setutxent();
	pututxline(utx);
	endutxent();	
# endif /* defined(HAVE_PUTUTXLINE) */
# if defined(HAVE_UPDWTMPX)
	updwtmpx(_PATH_WTMPX, utx);
# endif /* defined(HAVE_UPDWTMPX) */
#else /* defined(USE_UTMPX) */
# if defined(HAVE_PUTUTLINE)
	setutent();
	pututline(utp);
	endutent();	
# endif /* defined(HAVE_PUTUTLINE) */
# if defined(HAVE_UPDWTMPX)
	updwtmp(_PATH_WTMP, utp);
# endif /* defined(HAVE_UPDWTMP) */
#endif /* defined(USE_UTMPX) */

	/* Otherwise DIY */
#if (defined(USE_UTMPX) && !defined(HAVE_PUTUTXLINE)) || \
	(!defined(USE_UTMPX) && !defined(HAVE_PUTUTLINE)) 
	int fd;
	int tty;

	/* can't use ttyslot here, as that will not work for logout
	 * (record_logout() is called from the master sshd, which does
	 * not have the correct tty on stdin/out, so ttyslot will return
	 * "-1" or (worse) a wrong number
	 */
	tty = find_tty_slot(utp);

#ifdef USE_UTMPX
	/* If no tty was found, append it to utmpx */
	if (tty == -1) {
		if ((fd = open(_PATH_UTMPX, O_WRONLY|O_APPEND, 0)) >= 0) {
			(void)write(fd, utp, sizeof(struct utmp));
			(void)close(fd);
			return;
		}
	}
	/* Otherwise, tty was found - update at its location */
	fd = open(_PATH_UTMPX, O_RDWR|O_CREAT, 0644);
	if (fd == -1) {
		log("Couldn't open %s: %s", _PATH_UTMPX, strerror(errno));
		return;
	}
	lseek(fd, (off_t)(tty * sizeof(struct utmpx)), SEEK_SET);
	write(fd, utx, sizeof(struct utmpx));
	close(fd);
	if ((fd = open(_PATH_WTMPX, O_WRONLY|O_APPEND, 0)) >= 0) {
		(void)write(fd, utx, sizeof(struct utmpx));
		(void)close(fd);
	}
#else /* USE_UTMPX */
	/* If no tty was found, append it to utmp */
	if (tty == -1) {
		if ((fd = open(_PATH_UTMP, O_WRONLY|O_APPEND, 0)) >= 0) {
			(void)write(fd, utp, sizeof(struct utmp));
			(void)close(fd);
			return;
		}
	}
	/* Otherwise, tty was found - update at its location */
	fd = open(_PATH_UTMP, O_RDWR|O_CREAT, 0644);
	if (fd == -1) {
		log("Couldn't open %s: %s", _PATH_UTMP, strerror(errno));
		return;
	}
	lseek(fd, (off_t)(tty * sizeof(struct utmp)), SEEK_SET);
	write(fd, utp, sizeof(struct utmp));
	close(fd);
	if ((fd = open(_PATH_WTMP, O_WRONLY|O_APPEND, 0)) >= 0) {
		(void)write(fd, utp, sizeof(struct utmp));
		(void)close(fd);
	}
#endif /* USE_UTMPX */
#endif /* (defined(USE_UTMPX) && !defined(HAVE_PUTUTXLINE)) || \
			(!defined(USE_UTMPX) && !defined(HAVE_PUTUTLINE)) */
}

#endif /* HAVE_LOGIN */
