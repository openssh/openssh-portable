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
#include <utmp.h>
#include <stdio.h>

void
login(utp)
	struct utmp *utp;
{
	struct utmp old_ut;
	register int fd;
	int tty;

	tty = ttyslot();
	if (tty > 0 && (fd = open(_PATH_UTMP, O_RDWR|O_CREAT, 0644)) >= 0) {
#ifdef HAVE_HOST_IN_UTMP
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
#endif /* HAVE_HOST_IN_UTMP */
		(void)lseek(fd, (off_t)(tty * sizeof(struct utmp)), SEEK_SET);
		(void)write(fd, utp, sizeof(struct utmp));
		(void)close(fd);
	}
	if ((fd = open(_PATH_WTMP, O_WRONLY|O_APPEND, 0)) >= 0) {
		(void)write(fd, utp, sizeof(struct utmp));
		(void)close(fd);
	}
}

#endif /* HAVE_LOGIN */
