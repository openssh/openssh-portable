/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Created: Sat Mar 18 05:11:38 1995 ylo
 * Password authentication.  This file contains the functions to check whether
 * the password is valid for the user.
 */

#include "includes.h"

RCSID("$OpenBSD: auth-passwd.c,v 1.16 2000/06/20 01:39:38 markus Exp $");

#if !defined(USE_PAM) && !defined(HAVE_OSF_SIA)

#include "packet.h"
#include "ssh.h"
#include "servconf.h"
#include "xmalloc.h"

#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
#endif
#ifdef HAVE_HPUX_TRUSTED_SYSTEM_PW
# include <hpsecurity.h>
# include <prot.h>
#endif
#ifdef HAVE_SHADOW_H
# include <shadow.h>
#endif
#ifdef HAVE_GETPWANAM
# include <sys/label.h>
# include <sys/audit.h>
# include <pwdadj.h>
#endif
#if defined(HAVE_MD5_PASSWORDS) && !defined(HAVE_MD5_CRYPT)
# include "md5crypt.h"
#endif /* defined(HAVE_MD5_PASSWORDS) && !defined(HAVE_MD5_CRYPT) */

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
int
auth_password(struct passwd * pw, const char *password)
{
	extern ServerOptions options;
	char *encrypted_password;
	char *pw_password;
	char *salt;
#ifdef HAVE_SHADOW_H
	struct spwd *spw;
#endif
#ifdef HAVE_GETPWANAM
	struct passwd_adjunct *spw;
#endif
#ifdef WITH_AIXAUTHENTICATE
	char *authmsg;
	char *loginmsg;
	int reenter = 1;
#endif

	/* deny if no user. */
	if (pw == NULL)
		return 0;
	if (pw->pw_uid == 0 && options.permit_root_login == 2)
		return 0;
	if (*password == '\0' && options.permit_empty_passwd == 0)
		return 0;

#ifdef SKEY
	if (options.skey_authentication == 1) {
		int ret = auth_skey_password(pw, password);
		if (ret == 1 || ret == 0)
			return ret;
		/* Fall back to ordinary passwd authentication. */
	}
#endif

#ifdef WITH_AIXAUTHENTICATE
	return (authenticate(pw->pw_name,password,&reenter,&authmsg) == 0);
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

	pw_password = pw->pw_passwd;

#if defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	spw = getspnam(pw->pw_name);
	if (spw != NULL) 
	{
		/* Check for users with no password. */
		if (strcmp(password, "") == 0 && strcmp(spw->sp_pwdp, "") == 0)
			return 1;

		pw_password = spw->sp_pwdp;
	}
#endif /* defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW) */
#if defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	if (issecure() && (spw = getpwanam(pw->pw_name)) != NULL)
	{
		/* Check for users with no password. */
		if (strcmp(password, "") == 0 && strcmp(spw->pwa_passwd, "") == 0)
			return 1;

		pw_password = spw->pwa_passwd;
	}
#endif /* defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW) */

	if (pw_password[0] != '\0')
		salt = pw_password;
	else
		salt = "xx";

#ifdef HAVE_MD5_PASSWORDS
	if (is_md5_salt(salt))
		encrypted_password = md5_crypt(password, salt);
	else
		encrypted_password = crypt(password, salt);
#else /* HAVE_MD5_PASSWORDS */    
# ifdef HAVE_HPUX_TRUSTED_SYSTEM_PW
	encrypted_password = bigcrypt(password, salt);
# else
	encrypted_password = crypt(password, salt);
# endif /* HAVE_HPUX_TRUSTED_SYSTEM_PW */
#endif /* HAVE_MD5_PASSWORDS */    

	/* Authentication is accepted if the encrypted passwords are identical. */
	return (strcmp(encrypted_password, pw_password) == 0);
}
#endif /* !USE_PAM && !HAVE_OSF_SIA */
