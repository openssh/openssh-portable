/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
 *
 * $OpenBSD: auth.h,v 1.20 2001/06/26 06:32:47 itojun Exp $
 */
#ifndef AUTH_H
#define AUTH_H

#include "key.h"
#include "hostfile.h"
#include <openssl/rsa.h>

#ifdef HAVE_LOGIN_CAP
#include <login_cap.h>
#endif
#ifdef BSD_AUTH
#include <bsd_auth.h>
#endif

typedef struct Authctxt Authctxt;
typedef struct KbdintDevice KbdintDevice;

struct Authctxt {
	int success;
	int postponed;
	int valid;
	int attempt;
	int failures;
	char *user;
	char *service;
	struct passwd *pw;
	char *style;
	void *kbdintctxt;
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success 
 * query	returns: 0 - success, otherwise failure 
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
struct KbdintDevice
{
	const char *name;
	void*	(*init_ctx)	__P((Authctxt*));
	int	(*query)	__P((void *ctx, char **name, char **infotxt,
				u_int *numprompts, char ***prompts,
				u_int **echo_on));
	int	(*respond)	__P((void *ctx, u_int numresp, char **responses));
	void	(*free_ctx)	__P((void *ctx));
};

/*
 * Tries to authenticate the user using the .rhosts file.  Returns true if
 * authentication succeeds.  If ignore_rhosts is non-zero, this will not
 * consider .rhosts and .shosts (/etc/hosts.equiv will still be used).
 */
int     auth_rhosts(struct passwd *, const char *);

/* extended interface similar to auth_rhosts() */
int
auth_rhosts2(struct passwd *, const char *, const char *, const char *);

/*
 * Tries to authenticate the user using the .rhosts file and the host using
 * its host key.  Returns true if authentication succeeds.
 */
int
auth_rhosts_rsa(struct passwd *, const char *, RSA *);

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
int     auth_password(Authctxt *, const char *);

/*
 * Performs the RSA authentication dialog with the client.  This returns 0 if
 * the client could not be authenticated, and 1 if authentication was
 * successful.  This may exit if there is a serious protocol violation.
 */
int     auth_rsa(struct passwd *, BIGNUM *);

/*
 * Parses an RSA key (number of bits, e, n) from a string.  Moves the pointer
 * over the key.  Skips any whitespace at the beginning and at end.
 */
int     auth_rsa_read_key(char **, u_int *, BIGNUM *, BIGNUM *);

/*
 * Performs the RSA authentication challenge-response dialog with the client,
 * and returns true (non-zero) if the client gave the correct answer to our
 * challenge; returns zero if the client gives a wrong answer.
 */
int     auth_rsa_challenge_dialog(RSA *);

#ifdef KRB4
#include <krb.h>
/*
 * Performs Kerberos v4 mutual authentication with the client. This returns 0
 * if the client could not be authenticated, and 1 if authentication was
 * successful.  This may exit if there is a serious protocol violation.
 */
int     auth_krb4(const char *, KTEXT, char **);
int     krb4_init(uid_t);
void    krb4_cleanup_proc(void *);
int	auth_krb4_password(struct passwd *, const char *);

#ifdef AFS
#include <kafs.h>

/* Accept passed Kerberos v4 ticket-granting ticket and AFS tokens. */
int     auth_kerberos_tgt(struct passwd *, const char *);
int     auth_afs_token(struct passwd *, const char *);
#endif				/* AFS */

#endif				/* KRB4 */

#include "auth-pam.h"
#include "auth2-pam.h"

void	do_authentication(void);
void	do_authentication2(void);

Authctxt *authctxt_new(void);
void	auth_log(Authctxt *, int, char *, char *);
void	userauth_finish(Authctxt *, int, char *);
int	auth_root_allowed(char *);

int	auth2_challenge(Authctxt *, char *);

int	allowed_user(struct passwd *);

char	*get_challenge(Authctxt *);
int	verify_response(Authctxt *, const char *);

struct passwd * auth_get_user(void);

/* expand a filename - return buffer is allocated by xmalloc */
char	*expand_filename(const char *, struct passwd *);
char	*authorized_keys_file(struct passwd *);
char	*authorized_keys_file2(struct passwd *);

/* check a file and the path to it */
int
secure_filename(FILE *, const char *, struct passwd *, char *, size_t);

/* helper for hostbased auth */
HostStatus
check_key_in_hostfiles(struct passwd *, Key *, const char *,
    const char *, const char *);

#define AUTH_FAIL_MAX 6
#define AUTH_FAIL_LOG (AUTH_FAIL_MAX/2)
#define AUTH_FAIL_MSG "Too many authentication failures for %.100s"

#endif
