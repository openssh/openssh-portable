/*	$OpenBSD: pwcache.c,v 1.9 2005/08/08 08:05:34 espie Exp $ */
/*
 * Copyright (c) 1989, 1993
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
 * 3. Neither the name of the University nor the names of its contributors
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

#include <sys/types.h>

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

#define	NCACHE	64			/* power of 2 */
#define	MASK	(NCACHE - 1)		/* bits to store with */

char *
user_from_uid(uid_t uid, int nouser)
{
	static struct ncache {
		uid_t	uid;
		char	name[_PW_NAME_LEN + 1];
	} c_uid[NCACHE];
	static int pwopen;
	static char nbuf[15];		/* 32 bits == 10 digits */
	struct passwd *pw;
	struct ncache *cp;

	cp = c_uid + (uid & MASK);
	if (cp->uid != uid || !*cp->name) {
		if (pwopen == 0) {
			setpassent(1);
			pwopen = 1;
		}
		if ((pw = getpwuid(uid)) == NULL) {
			if (nouser)
				return (NULL);
			(void)snprintf(nbuf, sizeof(nbuf), "%u", uid);
			return (nbuf);
		}
		cp->uid = uid;
		strlcpy(cp->name, pw->pw_name, sizeof(cp->name));
	}
	return (cp->name);
}

char *
group_from_gid(gid_t gid, int nogroup)
{
	static struct ncache {
		gid_t	gid;
		char	name[_PW_NAME_LEN + 1];
	} c_gid[NCACHE];
	static int gropen;
	static char nbuf[15];		/* 32 bits == 10 digits */
	struct group *gr;
	struct ncache *cp;

	cp = c_gid + (gid & MASK);
	if (cp->gid != gid || !*cp->name) {
		if (gropen == 0) {
			setgroupent(1);
			gropen = 1;
		}
		if ((gr = getgrgid(gid)) == NULL) {
			if (nogroup)
				return (NULL);
			(void)snprintf(nbuf, sizeof(nbuf), "%u", gid);
			return (nbuf);
		}
		cp->gid = gid;
		strlcpy(cp->name, gr->gr_name, sizeof(cp->name));
	}
	return (cp->name);
}
