/*
 * Copyright (c) 2000 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char rcsid[] = "$OpenBSD: readpassphrase.c,v 1.5 2001/06/27 13:23:30 djm Exp $";
#endif /* LIBC_SCCS and not lint */

#include "includes.h"

#ifndef HAVE_READPASSPHRASE

#include <termios.h>
#include <readpassphrase.h>

#ifdef TCSASOFT
# define _T_FLUSH	(TCSAFLUSH|TCSASOFT)
#else
# define _T_FLUSH	(TCSAFLUSH)
#endif

char *
readpassphrase(prompt, buf, bufsiz, flags)
	const char *prompt;
	char *buf;
	size_t bufsiz;
	int flags;
{
	struct termios term;
	char ch, *p, *end;
#ifdef _POSIX_VDISABLE
	u_char status;
#endif
	int echo, input, output;
	sigset_t oset, nset;

	/* I suppose we could alloc on demand in this case (XXX). */
	if (bufsiz == 0) {
		errno = EINVAL;
		return(NULL);
	}

	/*
	 * Read and write to /dev/tty if available.  If not, read from
	 * stdin and write to stderr unless a tty is required.
	 */
	if ((input = output = open(_PATH_TTY, O_RDWR)) == -1) {
		if (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			return(NULL);
		}
		input = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * We block SIGINT and SIGTSTP so the terminal is not left
	 * in an inconsistent state (ie: no echo).  It would probably
	 * be better to simply catch these though.
	 */
	sigemptyset(&nset);
	sigaddset(&nset, SIGINT);
	sigaddset(&nset, SIGTSTP);
	(void)sigprocmask(SIG_BLOCK, &nset, &oset);

	/* Turn off echo if possible. */
	echo = 0;
#ifdef _POSIX_VDISABLE
	status = _POSIX_VDISABLE;
#endif
	if (tcgetattr(input, &term) == 0) {
		if (!(flags & RPP_ECHO_ON) && (term.c_lflag & ECHO)) {
			echo = 1;
			term.c_lflag &= ~ECHO;
		}
#ifdef VSTATUS
		if (term.c_cc[VSTATUS] != _POSIX_VDISABLE) {
			status = term.c_cc[VSTATUS];
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
		}
#endif
		(void)tcsetattr(input, _T_FLUSH, &term);
	}
	if (!(flags & RPP_ECHO_ON)) {
		if (tcgetattr(input, &term) == 0 && (term.c_lflag & ECHO)) {
			echo = 1;
			term.c_lflag &= ~ECHO;
			(void)tcsetattr(input, _T_FLUSH, &term);
		}
	}

	(void)write(output, prompt, strlen(prompt));
	end = buf + bufsiz - 1;
	for (p = buf; read(input, &ch, 1) == 1 && ch != '\n' && ch != '\r';) {
		if (p < end) {
			if ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			if (isalpha(ch)) {
				if ((flags & RPP_FORCELOWER))
					ch = tolower(ch);
				if ((flags & RPP_FORCEUPPER))
					ch = toupper(ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
#ifdef _POSIX_VDISABLE
	if (echo || status != _POSIX_VDISABLE) {
#else
	if (echo) {
#endif
		if (echo) {
			(void)write(output, "\n", 1);
			term.c_lflag |= ECHO;
		}
#ifdef VSTATUS
		if (status != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = status;
#endif
		(void)tcsetattr(input, _T_FLUSH, &term);
	}
	(void)sigprocmask(SIG_SETMASK, &oset, NULL);
	if (input != STDIN_FILENO)
		(void)close(input);
	return(buf);
}
#endif /* HAVE_READPASSPHRASE */

#if 0
char *
getpass(prompt)
        const char *prompt;
{
	static char buf[_PASSWORD_LEN + 1];

	return(readpassphrase(prompt, buf, sizeof(buf), RPP_ECHO_OFF));
}
#endif
