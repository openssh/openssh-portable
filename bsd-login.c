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

#if defined(LIBC_SCCS) && !defined(lint)
/* from: static char sccsid[] = "@(#)login.c	8.1 (Berkeley) 6/4/93"; */
static char *rcsid = "$OpenBSD: login.c,v 1.5 1998/07/13 02:11:12 millert Exp $";
#endif /* LIBC_SCCS and not lint */

#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#ifdef HAVE_UTMPX_H
# include <utmpx.h>
#endif
#ifdef HAVE_UTMP_H
# include <utmp.h>
#endif
#include <stdio.h>
#include <string.h>

void
login(utp)
	struct UTMP_STR *utp;
{
	struct UTMP_STR old_ut;
	register int fd;
	int tty;

#ifndef UT_LINESIZE
# define UT_LINESIZE (sizeof(old_ut.ut_line))
# ifdef HAVE_UTMPX_H
#  define UT_NAMESIZE (sizeof(old_ut.ut_user))
# else
#  define UT_NAMESIZE (sizeof(old_ut.ut_name))
# endif
# ifdef HAVE_HOST_IN_UTMP
#  define UT_HOSTSIZE (sizeof(old_ut.ut_host))
# endif
# ifdef HAVE_HOST_IN_UTMPX
#  define UT_HOSTSIZE (sizeof(old_ut.ut_host))
# endif
#endif

	tty = ttyslot();
	if (tty > 0 && (fd = open(_PATH_UTMP, O_RDWR|O_CREAT, 0644)) >= 0) {
#if defined(HAVE_HOST_IN_UTMP) || defined(HAVE_HOST_IN_UTMPX)
		(void)lseek(fd, (off_t)(tty * sizeof(struct UTMP_STR)), SEEK_SET);
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		if (read(fd, &old_ut, sizeof(struct UTMP_STR)) ==
		    sizeof(struct UTMP_STR) && utp->ut_host[0] == '\0' &&
		    old_ut.ut_host[0] != '\0' &&
		    strncmp(old_ut.ut_line, utp->ut_line, UT_LINESIZE) == 0 &&
		    strncmp(old_ut.ut_name, utp->ut_name, UT_NAMESIZE) == 0)
			(void)memcpy(utp->ut_host, old_ut.ut_host, UT_HOSTSIZE);
#endif /* defined(HAVE_HOST_IN_UTMP) || defined(HAVE_HOST_IN_UTMPX) */
		(void)lseek(fd, (off_t)(tty * sizeof(struct UTMP_STR)), SEEK_SET);
		(void)write(fd, utp, sizeof(struct UTMP_STR));
		(void)close(fd);
	}
	if ((fd = open(_PATH_WTMP, O_WRONLY|O_APPEND, 0)) >= 0) {
		(void)write(fd, utp, sizeof(struct UTMP_STR));
		(void)close(fd);
	}
}

#endif /* HAVE_LOGIN */
