/*
 * Copyright (c) 2000 Markus Friedl. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"
RCSID("$OpenBSD: auth.c,v 1.15 2001/02/03 10:08:37 markus Exp $");

#ifdef HAVE_LOGIN_H
#include <login.h>
#endif
#if defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#include <shadow.h>
#endif /* defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW) */

#include "xmalloc.h"
#include "match.h"
#include "groupaccess.h"
#include "log.h"
#include "servconf.h"
#include "auth.h"
#include "auth-options.h"
#include "canohost.h"

/* import */
extern ServerOptions options;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
int
allowed_user(struct passwd * pw)
{
	struct stat st;
	char *shell;
	int i;
#ifdef WITH_AIXAUTHENTICATE
	char *loginmsg;
#endif /* WITH_AIXAUTHENTICATE */
#if !defined(USE_PAM) && defined(HAVE_SHADOW_H) && \
	!defined(DISABLE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	struct spwd *spw;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	if (!pw || !pw->pw_name)
		return 0;

	spw = getspnam(pw->pw_name);
	if (spw != NULL) {
		int days = time(NULL) / 86400;

		/* Check account expiry */
		if ((spw->sp_expire >= 0) && (days > spw->sp_expire))
			return 0;

		/* Check password expiry */
		if ((spw->sp_lstchg >= 0) && (spw->sp_max >= 0) &&
		    (days > (spw->sp_lstchg + spw->sp_max)))
			return 0;
	}
#else
	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	if (!pw || !pw->pw_name)
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
		for (i = 0; i < options.num_deny_users; i++)
			if (match_pattern(pw->pw_name, options.deny_users[i]))
				return 0;
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	if (options.num_allow_users > 0) {
		for (i = 0; i < options.num_allow_users; i++)
			if (match_pattern(pw->pw_name, options.allow_users[i]))
				break;
		/* i < options.num_allow_users iff we break for loop */
		if (i >= options.num_allow_users)
			return 0;
	}
	if (options.num_deny_groups > 0 || options.num_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		if (ga_init(pw->pw_name, pw->pw_gid) == 0)
			return 0;

		/* Return false if one of user's groups is listed in DenyGroups */
		if (options.num_deny_groups > 0)
			if (ga_match(options.deny_groups,
			    options.num_deny_groups)) {
				ga_free();
				return 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		if (options.num_allow_groups > 0)
			if (!ga_match(options.allow_groups,
			    options.num_allow_groups)) {
				ga_free();
				return 0;
			}
		ga_free();
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

Authctxt *
authctxt_new(void)
{
	Authctxt *authctxt = xmalloc(sizeof(*authctxt));
	memset(authctxt, 0, sizeof(*authctxt));
	return authctxt;
}

struct passwd *
pwcopy(struct passwd *pw)
{
	struct passwd *copy = xmalloc(sizeof(*copy));
	memset(copy, 0, sizeof(*copy));
	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd);
	copy->pw_uid = pw->pw_uid;
	copy->pw_gid = pw->pw_gid;
#ifdef HAVE_PW_CLASS_IN_PASSWD
	copy->pw_class = xstrdup(pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell);
	return copy;
}

void
auth_log(Authctxt *authctxt, int authenticated, char *method, char *info)
{
	void (*authlog) (const char *fmt,...) = verbose;
	char *authmsg;

	/* Raise logging level */
	if (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= AUTH_FAIL_LOG ||
	    strcmp(method, "password") == 0)
		authlog = log;

	if (authctxt->postponed)
		authmsg = "Postponed";
	else
		authmsg = authenticated ? "Accepted" : "Failed";

	authlog("%s %s for %s%.100s from %.200s port %d%s",
	    authmsg,
	    method,
	    authctxt->valid ? "" : "illegal user ",
	    authctxt->valid && authctxt->pw->pw_uid == 0 ? "ROOT" : authctxt->user,
	    get_remote_ipaddr(),
	    get_remote_port(),
	    info);
}

/*
 * Check if the user is logging in as root and root logins are disallowed.
 * Note that root login is _allways_ allowed for forced commands.
 */
int
auth_root_allowed(void)
{
	if (options.permit_root_login)
		return 1;
	if (forced_command) {
		log("Root login accepted for forced command.");
		return 1;
	} else {
		log("ROOT LOGIN REFUSED FROM %.200s", get_remote_ipaddr());
		return 0;
	}
}
