/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Created: Sat Mar 18 05:11:38 1995 ylo
 * Password authentication.  This file contains the functions to check whether
 * the password is valid for the user.
 */

#include "includes.h"

#ifndef HAVE_PAM

RCSID("$Id: auth-passwd.c,v 1.10 1999/12/21 10:03:09 damien Exp $");

#include "packet.h"
#include "ssh.h"
#include "servconf.h"
#include "xmalloc.h"

#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif

#ifdef HAVE_MD5_PASSWORDS
#include "md5crypt.h"
#endif

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
int 
auth_password(struct passwd * pw, const char *password)
{
	extern ServerOptions options;
	char *encrypted_password;
#ifdef HAVE_SHADOW_H
	struct spwd *spw;
#endif

	if (pw->pw_uid == 0 && options.permit_root_login == 2)
		return 0;
	if (*password == '\0' && options.permit_empty_passwd == 0)
		return 0;
	/* deny if no user. */
	if (pw == NULL)
		return 0;

#ifdef SKEY
	if (options.skey_authentication == 1) {
		int ret = auth_skey_password(pw, password);
		if (ret == 1 || ret == 0)
			return ret;
		/* Fall back to ordinary passwd authentication. */
	}
#endif
#ifdef KRB4
	if (options.kerberos_authentication == 1) {
		int ret = auth_krb4_password(pw, password);
		if (ret == 1 || ret == 0)
			return ret;
		/* Fall back to ordinary passwd authentication. */
	}
#endif

	/* Check for users with no password. */
	if (strcmp(password, "") == 0 && strcmp(pw->pw_passwd, "") == 0)
		return 1;

#if defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	spw = getspnam(pw->pw_name);
	if (spw == NULL)
		return(0);

	if ((spw->sp_namp == NULL) || (strcmp(pw->pw_name, spw->sp_namp) != 0))
		fatal("Shadow lookup returned garbage.");

	/* Check for users with no password. */
	if (strcmp(password, "") == 0 && strcmp(spw->sp_pwdp, "") == 0)
		return 1;

	if (strlen(spw->sp_pwdp) < 3)
		return(0);

	/* Encrypt the candidate password using the proper salt. */
#ifdef HAVE_MD5_PASSWORDS
	if (is_md5_salt(spw->sp_pwdp))
		encrypted_password = md5_crypt(password, spw->sp_pwdp);
	else
		encrypted_password = crypt(password, spw->sp_pwdp);
#else /* HAVE_MD5_PASSWORDS */    
	encrypted_password = crypt(password, spw->sp_pwdp);
#endif /* HAVE_MD5_PASSWORDS */    
	/* Authentication is accepted if the encrypted passwords are identical. */
	return (strcmp(encrypted_password, spw->sp_pwdp) == 0);
#else /* defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW) */

	if (strlen(pw->pw_passwd) < 3)
		return(0);

#ifdef HAVE_MD5_PASSWORDS
	if (is_md5_salt(pw->pw_passwd))
		encrypted_password = md5_crypt(password, pw->pw_passwd);
	else
		encrypted_password = crypt(password, pw->pw_passwd);
#else /* HAVE_MD5_PASSWORDS */    
	encrypted_password = crypt(password, pw->pw_passwd);
#endif /* HAVE_MD5_PASSWORDS */    

	/* Authentication is accepted if the encrypted passwords are identical. */
	return (strcmp(encrypted_password, pw->pw_passwd) == 0);
#endif /* defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW) */
}
#endif /* !HAVE_PAM */
