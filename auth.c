/*
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Copyright (c) 2000 Markus Friedl. All rights reserved.
 */

#include "includes.h"
RCSID("$OpenBSD: auth.c,v 1.2 2000/04/06 08:55:22 markus Exp $");

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

#include "bufaux.h"
#include "ssh2.h"
#include "auth.h"
#include "session.h"
#include "dispatch.h"


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
static int
allowed_user(struct passwd * pw)
{
	struct stat st;
	struct group *grp;
	int i;
#ifdef WITH_AIXAUTHENTICATE
	char *loginmsg;
#endif /* WITH_AIXAUTHENTICATE */

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	if (!pw)
		return 0;

	/* deny if shell does not exists or is not executable */
	if (stat(pw->pw_shell, &st) != 0)
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
	if (loginrestrictions(pw->pw_name,S_LOGIN,NULL,&loginmsg) != 0)
		return 0;
#endif /* WITH_AIXAUTHENTICATE */

	/* We found no reason not to let this user try to log on... */
	return 1;
}

/*
 * convert ssh auth msg type into description
 */
char *
get_authname(int type)
{
	static char buf[1024];
	switch (type) {
	case SSH_CMSG_AUTH_PASSWORD:
		return "password";
	case SSH_CMSG_AUTH_RSA:
		return "rsa";
	case SSH_CMSG_AUTH_RHOSTS_RSA:
		return "rhosts-rsa";
	case SSH_CMSG_AUTH_RHOSTS:
		return "rhosts";
#ifdef KRB4
	case SSH_CMSG_AUTH_KERBEROS:
		return "kerberos";
#endif
#ifdef SKEY
	case SSH_CMSG_AUTH_TIS_RESPONSE:
		return "s/key";
#endif
	}
	snprintf(buf, sizeof buf, "bad-auth-msg-%d", type);
	return buf;
}

#define AUTH_FAIL_MAX 6
#define AUTH_FAIL_LOG (AUTH_FAIL_MAX/2)
#define AUTH_FAIL_MSG "Too many authentication failures for %.100s"

/*
 * The user does not exist or access is denied,
 * but fake indication that authentication is needed.
 */
void
do_fake_authloop1(char *user)
{
	int attempt = 0;

	log("Faking authloop for illegal user %.200s from %.200s port %d",
	    user,
	    get_remote_ipaddr(),
	    get_remote_port());

#ifdef WITH_AIXAUTHENTICATE 
		if (strncmp(get_authname(type),"password",
		    strlen(get_authname(type))) == 0)
			loginfailed(pw->pw_name,get_canonical_hostname(),"ssh");
#endif /* WITH_AIXAUTHENTICATE */

	/* Indicate that authentication is needed. */
	packet_start(SSH_SMSG_FAILURE);
	packet_send();
	packet_write_wait();

	/*
	 * Keep reading packets, and always respond with a failure.  This is
	 * to avoid disclosing whether such a user really exists.
	 */
	for (attempt = 1;; attempt++) {
		/* Read a packet.  This will not return if the client disconnects. */
		int plen;
#ifndef SKEY
		(void)packet_read(&plen);
#else /* SKEY */
		int type = packet_read(&plen);
		unsigned int dlen;
		char *password, *skeyinfo;
		/* Try to send a fake s/key challenge. */
		if (options.skey_authentication == 1 &&
		    (skeyinfo = skey_fake_keyinfo(user)) != NULL) {
			password = NULL;
			if (type == SSH_CMSG_AUTH_TIS) {
				packet_start(SSH_SMSG_AUTH_TIS_CHALLENGE);
				packet_put_string(skeyinfo, strlen(skeyinfo));
				packet_send();
				packet_write_wait();
				continue;
			} else if (type == SSH_CMSG_AUTH_PASSWORD &&
			           options.password_authentication &&
			           (password = packet_get_string(&dlen)) != NULL &&
			           dlen == 5 &&
			           strncasecmp(password, "s/key", 5) == 0 ) {
				packet_send_debug(skeyinfo);
			}
			if (password != NULL)
				xfree(password);
		}
#endif
		if (attempt > AUTH_FAIL_MAX)
			packet_disconnect(AUTH_FAIL_MSG, user);

		/*
		 * Send failure.  This should be indistinguishable from a
		 * failed authentication.
		 */
		packet_start(SSH_SMSG_FAILURE);
		packet_send();
		packet_write_wait();
	}
	/* NOTREACHED */
	abort();
}

/*
 * read packets and try to authenticate local user *pw.
 * return if authentication is successfull
 */
void
do_authloop(struct passwd * pw)
{
	int attempt = 0;
	unsigned int bits;
	RSA *client_host_key;
	BIGNUM *n;
	char *client_user = NULL, *password = NULL;
	char user[1024];
	unsigned int dlen;
	int plen, nlen, elen;
	unsigned int ulen;
	int type = 0;
	void (*authlog) (const char *fmt,...) = verbose;

	/* Indicate that authentication is needed. */
	packet_start(SSH_SMSG_FAILURE);
	packet_send();
	packet_write_wait();

	for (attempt = 1;; attempt++) {
		int authenticated = 0;
		strlcpy(user, "", sizeof user);

		/* Get a packet from the client. */
		type = packet_read(&plen);

		/* Process the packet. */
		switch (type) {
#ifdef AFS
		case SSH_CMSG_HAVE_KERBEROS_TGT:
			if (!options.kerberos_tgt_passing) {
				/* packet_get_all(); */
				verbose("Kerberos tgt passing disabled.");
				break;
			} else {
				/* Accept Kerberos tgt. */
				char *tgt = packet_get_string(&dlen);
				packet_integrity_check(plen, 4 + dlen, type);
				if (!auth_kerberos_tgt(pw, tgt))
					verbose("Kerberos tgt REFUSED for %s", pw->pw_name);
				xfree(tgt);
			}
			continue;

		case SSH_CMSG_HAVE_AFS_TOKEN:
			if (!options.afs_token_passing || !k_hasafs()) {
				/* packet_get_all(); */
				verbose("AFS token passing disabled.");
				break;
			} else {
				/* Accept AFS token. */
				char *token_string = packet_get_string(&dlen);
				packet_integrity_check(plen, 4 + dlen, type);
				if (!auth_afs_token(pw, token_string))
					verbose("AFS token REFUSED for %s", pw->pw_name);
				xfree(token_string);
			}
			continue;
#endif /* AFS */
#ifdef KRB4
		case SSH_CMSG_AUTH_KERBEROS:
			if (!options.kerberos_authentication) {
				/* packet_get_all(); */
				verbose("Kerberos authentication disabled.");
				break;
			} else {
				/* Try Kerberos v4 authentication. */
				KTEXT_ST auth;
				char *tkt_user = NULL;
				char *kdata = packet_get_string((unsigned int *) &auth.length);
				packet_integrity_check(plen, 4 + auth.length, type);

				if (auth.length < MAX_KTXT_LEN)
					memcpy(auth.dat, kdata, auth.length);
				xfree(kdata);

				authenticated = auth_krb4(pw->pw_name, &auth, &tkt_user);

				if (authenticated) {
					snprintf(user, sizeof user, " tktuser %s", tkt_user);
					xfree(tkt_user);
				}
			}
			break;
#endif /* KRB4 */

		case SSH_CMSG_AUTH_RHOSTS:
			if (!options.rhosts_authentication) {
				verbose("Rhosts authentication disabled.");
				break;
			}
			/*
			 * Get client user name.  Note that we just have to
			 * trust the client; this is one reason why rhosts
			 * authentication is insecure. (Another is
			 * IP-spoofing on a local network.)
			 */
			client_user = packet_get_string(&ulen);
			packet_integrity_check(plen, 4 + ulen, type);

			/* Try to authenticate using /etc/hosts.equiv and
			   .rhosts. */
			authenticated = auth_rhosts(pw, client_user);

			snprintf(user, sizeof user, " ruser %s", client_user);
			break;

		case SSH_CMSG_AUTH_RHOSTS_RSA:
			if (!options.rhosts_rsa_authentication) {
				verbose("Rhosts with RSA authentication disabled.");
				break;
			}
			/*
			 * Get client user name.  Note that we just have to
			 * trust the client; root on the client machine can
			 * claim to be any user.
			 */
			client_user = packet_get_string(&ulen);

			/* Get the client host key. */
			client_host_key = RSA_new();
			if (client_host_key == NULL)
				fatal("RSA_new failed");
			client_host_key->e = BN_new();
			client_host_key->n = BN_new();
			if (client_host_key->e == NULL || client_host_key->n == NULL)
				fatal("BN_new failed");
			bits = packet_get_int();
			packet_get_bignum(client_host_key->e, &elen);
			packet_get_bignum(client_host_key->n, &nlen);

			if (bits != BN_num_bits(client_host_key->n))
				error("Warning: keysize mismatch for client_host_key: "
				      "actual %d, announced %d", BN_num_bits(client_host_key->n), bits);
			packet_integrity_check(plen, (4 + ulen) + 4 + elen + nlen, type);

			authenticated = auth_rhosts_rsa(pw, client_user, client_host_key);
			RSA_free(client_host_key);

			snprintf(user, sizeof user, " ruser %s", client_user);
			break;

		case SSH_CMSG_AUTH_RSA:
			if (!options.rsa_authentication) {
				verbose("RSA authentication disabled.");
				break;
			}
			/* RSA authentication requested. */
			n = BN_new();
			packet_get_bignum(n, &nlen);
			packet_integrity_check(plen, nlen, type);
			authenticated = auth_rsa(pw, n);
			BN_clear_free(n);
			break;

		case SSH_CMSG_AUTH_PASSWORD:
			if (!options.password_authentication) {
				verbose("Password authentication disabled.");
				break;
			}
			/*
			 * Read user password.  It is in plain text, but was
			 * transmitted over the encrypted channel so it is
			 * not visible to an outside observer.
			 */
			password = packet_get_string(&dlen);
			packet_integrity_check(plen, 4 + dlen, type);

#ifdef USE_PAM
			/* Do PAM auth with password */
			authenticated = auth_pam_password(pw, password);
#else /* USE_PAM */
			/* Try authentication with the password. */
			authenticated = auth_password(pw, password);
#endif /* USE_PAM */
			memset(password, 0, strlen(password));
			xfree(password);
			break;

#ifdef SKEY
		case SSH_CMSG_AUTH_TIS:
			debug("rcvd SSH_CMSG_AUTH_TIS");
			if (options.skey_authentication == 1) {
				char *skeyinfo = skey_keyinfo(pw->pw_name);
				if (skeyinfo == NULL) {
					debug("generating fake skeyinfo for %.100s.", pw->pw_name);
					skeyinfo = skey_fake_keyinfo(pw->pw_name);
				}
				if (skeyinfo != NULL) {
					/* we send our s/key- in tis-challenge messages */
					debug("sending challenge '%s'", skeyinfo);
					packet_start(SSH_SMSG_AUTH_TIS_CHALLENGE);
					packet_put_string(skeyinfo, strlen(skeyinfo));
					packet_send();
					packet_write_wait();
					continue;
				}
			}
			break;
		case SSH_CMSG_AUTH_TIS_RESPONSE:
			debug("rcvd SSH_CMSG_AUTH_TIS_RESPONSE");
			if (options.skey_authentication == 1) {
				char *response = packet_get_string(&dlen);
				debug("skey response == '%s'", response);
				packet_integrity_check(plen, 4 + dlen, type);
				authenticated = (skey_haskey(pw->pw_name) == 0 &&
						 skey_passcheck(pw->pw_name, response) != -1);
				xfree(response);
			}
			break;
#else
		case SSH_CMSG_AUTH_TIS:
			/* TIS Authentication is unsupported */
			log("TIS authentication unsupported.");
			break;
#endif

		default:
			/*
			 * Any unknown messages will be ignored (and failure
			 * returned) during authentication.
			 */
			log("Unknown message during authentication: type %d", type);
			break;
		}

 		/*
 		 * Check if the user is logging in as root and root logins
 		 * are disallowed.
 		 * Note that root login is allowed for forced commands.
 		 */
 		if (authenticated && pw->pw_uid == 0 && !options.permit_root_login) {
 			if (forced_command) {
 				log("Root login accepted for forced command.");
 			} else {
 				authenticated = 0;
 				log("ROOT LOGIN REFUSED FROM %.200s",
 				    get_canonical_hostname());
 			}
  		}

		/* Raise logging level */
		if (authenticated ||
		    attempt == AUTH_FAIL_LOG ||
		    type == SSH_CMSG_AUTH_PASSWORD)
			authlog = log;

		authlog("%s %s for %.200s from %.200s port %d%s",
			authenticated ? "Accepted" : "Failed",
			get_authname(type),
			pw->pw_uid == 0 ? "ROOT" : pw->pw_name,
			get_remote_ipaddr(),
			get_remote_port(),
			user);

#ifdef USE_PAM
		if (authenticated) {
			if (!do_pam_account(pw->pw_name, client_user)) {
				if (client_user != NULL) {
					xfree(client_user);
					client_user = NULL;
				}
				do_fake_authloop1(pw->pw_name);
			}
			return;
		}
#else /* USE_PAM */
		if (authenticated) {
			return;
		}
#endif /* USE_PAM */

		if (client_user != NULL) {
			xfree(client_user);
			client_user = NULL;
		}

		if (attempt > AUTH_FAIL_MAX)
			packet_disconnect(AUTH_FAIL_MSG, pw->pw_name);

		/* Send a message indicating that the authentication attempt failed. */
		packet_start(SSH_SMSG_FAILURE);
		packet_send();
		packet_write_wait();
	}
}

/*
 * Performs authentication of an incoming connection.  Session key has already
 * been exchanged and encryption is enabled.
 */
void
do_authentication()
{
	struct passwd *pw, pwcopy;
	int plen;
	unsigned int ulen;
	char *user;
#ifdef WITH_AIXAUTHENTICATE
	char *loginmsg;
#endif /* WITH_AIXAUTHENTICATE */

	/* Get the name of the user that we wish to log in as. */
	packet_read_expect(&plen, SSH_CMSG_USER);

	/* Get the user name. */
	user = packet_get_string(&ulen);
	packet_integrity_check(plen, (4 + ulen), SSH_CMSG_USER);

	setproctitle("%s", user);

#ifdef AFS
	/* If machine has AFS, set process authentication group. */
	if (k_hasafs()) {
		k_setpag();
		k_unlog();
	}
#endif /* AFS */

	/* Verify that the user is a valid user. */
	pw = getpwnam(user);
	if (!pw || !allowed_user(pw))
		do_fake_authloop1(user);
	xfree(user);

	/* Take a copy of the returned structure. */
	memset(&pwcopy, 0, sizeof(pwcopy));
	pwcopy.pw_name = xstrdup(pw->pw_name);
	pwcopy.pw_passwd = xstrdup(pw->pw_passwd);
	pwcopy.pw_uid = pw->pw_uid;
	pwcopy.pw_gid = pw->pw_gid;
	pwcopy.pw_dir = xstrdup(pw->pw_dir);
	pwcopy.pw_shell = xstrdup(pw->pw_shell);
	pw = &pwcopy;

#ifdef USE_PAM
	start_pam(pw);
#endif

	/*
	 * If we are not running as root, the user must have the same uid as
	 * the server.
	 */
	if (getuid() != 0 && pw->pw_uid != getuid())
		packet_disconnect("Cannot change user when server not running as root.");

	debug("Attempting authentication for %.100s.", pw->pw_name);

	/* If the user has no password, accept authentication immediately. */
	if (options.password_authentication &&
#ifdef KRB4
	    (!options.kerberos_authentication || options.kerberos_or_local_passwd) &&
#endif /* KRB4 */
#ifdef USE_PAM
	    auth_pam_password(pw, "")) {
#else /* USE_PAM */
	    auth_password(pw, "")) {
#endif /* USE_PAM */
		/* Authentication with empty password succeeded. */
		log("Login for user %s from %.100s, accepted without authentication.",
		    pw->pw_name, get_remote_ipaddr());
	} else {
		/* Loop until the user has been authenticated or the
		   connection is closed, do_authloop() returns only if
		   authentication is successfull */
		do_authloop(pw);
	}

	/* The user has been authenticated and accepted. */
#ifdef WITH_AIXAUTHENTICATE
	loginsuccess(user,get_canonical_hostname(),"ssh",&loginmsg);
#endif /* WITH_AIXAUTHENTICATE */
	packet_start(SSH_SMSG_SUCCESS);
	packet_send();
	packet_write_wait();

	/* Perform session preparation. */
	do_authenticated(pw);
}


void input_service_request(int type, int plen);
void input_userauth_request(int type, int plen);
void ssh2_pty_cleanup(void);

typedef struct Authctxt Authctxt;
struct Authctxt {
	char *user;
	char *service;
	struct passwd pw;
	int valid;
};
static Authctxt	*authctxt = NULL;
static int userauth_success = 0;

struct passwd*
auth_get_user(void)
{
	return (authctxt != NULL && authctxt->valid) ? &authctxt->pw : NULL;
}
struct passwd*
auth_set_user(char *u, char *s)
{
	struct passwd *pw, *copy;

	if (authctxt == NULL) {
		authctxt = xmalloc(sizeof(*authctxt));
		authctxt->valid = 0;
		authctxt->user = xstrdup(u);
		authctxt->service = xstrdup(s);
		setproctitle("%s", u);
		pw = getpwnam(u);
		if (!pw || !allowed_user(pw)) {
			log("auth_set_user: bad user %s", u);
			return NULL;
		}
#ifdef USE_PAM
		start_pam(pw);
#endif
		copy = &authctxt->pw;
		memset(copy, 0, sizeof(*copy));
		copy->pw_name = xstrdup(pw->pw_name);
		copy->pw_passwd = xstrdup(pw->pw_passwd);
		copy->pw_uid = pw->pw_uid;
		copy->pw_gid = pw->pw_gid;
		copy->pw_dir = xstrdup(pw->pw_dir);
		copy->pw_shell = xstrdup(pw->pw_shell);
		authctxt->valid = 1;
	} else {
		if (strcmp(u, authctxt->user) != 0 ||
		    strcmp(s, authctxt->service) != 0) {
			log("auth_set_user: missmatch: (%s,%s)!=(%s,%s)",
			    u, s, authctxt->user, authctxt->service);
			return NULL;
		}
	}
	return auth_get_user();
}

static void
protocol_error(int type, int plen)
{
	log("auth: protocol error: type %d plen %d", type, plen);
	packet_start(SSH2_MSG_UNIMPLEMENTED);
	packet_put_int(0);
	packet_send();
	packet_write_wait();
}
void
input_service_request(int type, int plen)
{
	unsigned int len;
	int accept = 0;
	char *service = packet_get_string(&len);

	if (strcmp(service, "ssh-userauth") == 0) {
		if (!userauth_success) {
			accept = 1;
			/* now we can handle user-auth requests */
			dispatch_set(SSH2_MSG_USERAUTH_REQUEST, &input_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	if (accept) {
		packet_start(SSH2_MSG_SERVICE_ACCEPT);
		packet_put_cstring(service);
		packet_send();
		packet_write_wait();
	} else {
		debug("bad service request %s", service);
		packet_disconnect("bad service request %s", service);
	}
	xfree(service);
}
void
input_userauth_request(int type, int plen)
{
	static int try = 0;
	unsigned int len;
	int c, authenticated = 0;
	char *user, *service, *method;
	struct passwd *pw;

	if (++try == AUTH_FAIL_MAX)
		packet_disconnect("too many failed userauth_requests");

	user = packet_get_string(&len);
	service = packet_get_string(&len);
	method = packet_get_string(&len);
	debug("userauth-request for user %s service %s method %s", user, service, method);

	/* XXX we only allow the ssh-connection service */
	pw = auth_set_user(user, service);
	if (pw && strcmp(service, "ssh-connection")==0) {
		if (strcmp(method, "none") == 0 && try == 1) {
#ifdef USE_PAM
			/* Do PAM auth with password */
			authenticated = auth_pam_password(pw, "");
#else /* USE_PAM */
			/* Try authentication with the password. */
			authenticated = auth_password(pw, "");
#endif /* USE_PAM */
		} else if (strcmp(method, "password") == 0) {
			char *password;
			c = packet_get_char();
			if (c)
				debug("password change not supported");
			password = packet_get_string(&len);
#ifdef USE_PAM
			/* Do PAM auth with password */
			authenticated = auth_pam_password(pw, password);
#else /* USE_PAM */
			/* Try authentication with the password. */
			authenticated = auth_password(pw, password);
#endif /* USE_PAM */
			memset(password, 0, len);
			xfree(password);
		} else if (strcmp(method, "publickey") == 0) {
			/* XXX TODO */
			char *pkalg;
			char *pkblob;
			c = packet_get_char();
			pkalg = packet_get_string(&len);
			pkblob = packet_get_string(&len);
			xfree(pkalg);
			xfree(pkblob);
		}
	}
	/* XXX check if other auth methods are needed */
	if (authenticated) {
		/* turn off userauth */
		dispatch_set(SSH2_MSG_USERAUTH_REQUEST, &protocol_error);
		/* success! */
		packet_start(SSH2_MSG_USERAUTH_SUCCESS);
		packet_send();
		packet_write_wait();
		log("userauth success for %s", user);
		/* now we can break out */
		userauth_success = 1;
	} else {
		packet_start(SSH2_MSG_USERAUTH_FAILURE);
		packet_put_cstring("password");
		packet_put_char(0);		/* partial success */
		packet_send();
		packet_write_wait();
	}
	xfree(service);
	xfree(user);
	xfree(method);
}
void 
do_authentication2()
{
	dispatch_init(&protocol_error);
	dispatch_set(SSH2_MSG_SERVICE_REQUEST, &input_service_request);
	dispatch_run(DISPATCH_BLOCK, &userauth_success);
	do_authenticated2();
}
