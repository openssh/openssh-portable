/*
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Copyright (c) 2000 Markus Friedl. All rights reserved.
 */

#include "includes.h"
RCSID("$OpenBSD: auth.c,v 1.8 2000/08/04 20:30:07 markus Exp $");

#include "xmalloc.h"
#include "rsa.h"
#include "ssh.h"
#include "pty.h"
#include "packet.h"
#include "buffer.h"
#include "cipher.h"
#include "mpaux.h"
#include "servconf.h"
#include "compat.h"
#include "channels.h"
#include "match.h"
#ifdef HAVE_LOGIN_H
#include <login.h>
#endif
#if defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#include <shadow.h>
#endif /* defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW) */

#include "bufaux.h"
#include "ssh2.h"
#include "auth.h"
#include "session.h"

/* import */
extern ServerOptions options;
extern char *forced_command;

/*
 * Check if the user is allowed to log in via ssh. If user is listed in
 * DenyUsers or user's primary group is listed in DenyGroups, false will
 * be returned. If AllowUsers isn't empty and user isn't listed there, or
 * if AllowGroups isn't empty and user isn't listed there, false will be
 * returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
int
allowed_user(struct passwd * pw)
{
	struct stat st;
	struct group *grp;
	char *shell;
	int i;
#ifdef WITH_AIXAUTHENTICATE
	char *loginmsg;
#endif /* WITH_AIXAUTHENTICATE */
#if defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW) && \
	defined(HAS_SHADOW_EXPIRE)
  struct spwd *spw;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	if (!pw)
		return 0;

	spw = getspnam(pw->pw_name);
	if (spw != NULL) {
		int days = time(NULL) / 86400;

		/* Check account expiry */
		if ((spw->sp_expire > 0) && (days > spw->sp_expire))
			return 0;

		/* Check password expiry */
		if ((spw->sp_lstchg > 0) && (spw->sp_inact > 0) && 
			(days > (spw->sp_lstchg + spw->sp_inact)))
			return 0;
	}
#else
	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	if (!pw)
		return 0;
#endif

	/*
	 * Get the shell from the password data.  An empty shell field is
	 * legal, and means /bin/sh.
	 */
	shell = (pw->pw_shell[0] == '\0') ? _PATH_BSHELL : pw->pw_shell;

	/* deny if shell does not exists or is not executable */
	if (stat(shell, &st) != 0)
		return 0;
	if (!((st.st_mode & S_IFREG) && (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP))))
		return 0;

	/* Return false if user is listed in DenyUsers */
	if (options.num_deny_users > 0) {
		if (!pw->pw_name)
			return 0;
		for (i = 0; i < options.num_deny_users; i++)
			if (match_pattern(pw->pw_name, options.deny_users[i]))
				return 0;
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	if (options.num_allow_users > 0) {
		if (!pw->pw_name)
			return 0;
		for (i = 0; i < options.num_allow_users; i++)
			if (match_pattern(pw->pw_name, options.allow_users[i]))
				break;
		/* i < options.num_allow_users iff we break for loop */
		if (i >= options.num_allow_users)
			return 0;
	}
	/* Get the primary group name if we need it. Return false if it fails */
	if (options.num_deny_groups > 0 || options.num_allow_groups > 0) {
		grp = getgrgid(pw->pw_gid);
		if (!grp)
			return 0;

		/* Return false if user's group is listed in DenyGroups */
		if (options.num_deny_groups > 0) {
			if (!grp->gr_name)
				return 0;
			for (i = 0; i < options.num_deny_groups; i++)
				if (match_pattern(grp->gr_name, options.deny_groups[i]))
					return 0;
		}
		/*
		 * Return false if AllowGroups isn't empty and user's group
		 * isn't listed there
		 */
		if (options.num_allow_groups > 0) {
			if (!grp->gr_name)
				return 0;
			for (i = 0; i < options.num_allow_groups; i++)
				if (match_pattern(grp->gr_name, options.allow_groups[i]))
					break;
			/* i < options.num_allow_groups iff we break for
			   loop */
			if (i >= options.num_allow_groups)
				return 0;
		}
	}

#ifdef WITH_AIXAUTHENTICATE
	if (loginrestrictions(pw->pw_name, S_RLOGIN, NULL, &loginmsg) != 0) {
		if (loginmsg && *loginmsg) {
			/* Remove embedded newlines (if any) */
			char *p;
			for (p = loginmsg; *p; p++) {
				if (*p == '\n')
					*p = ' ';
			}
			/* Remove trailing newline */
			*--p = '\0';
			log("Login restricted for %s: %.100s", pw->pw_name, loginmsg);
		}
		return 0;
	}
#endif /* WITH_AIXAUTHENTICATE */

	/* We found no reason not to let this user try to log on... */
	return 1;
}
