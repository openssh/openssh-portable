/*
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"
RCSID("$OpenBSD: auth1.c,v 1.25 2001/06/26 16:15:23 dugsong Exp $");

#include "xmalloc.h"
#include "rsa.h"
#include "ssh1.h"
#include "packet.h"
#include "buffer.h"
#include "mpaux.h"
#include "log.h"
#include "servconf.h"
#include "compat.h"
#include "auth.h"
#include "session.h"
#include "misc.h"
#include "uidswap.h"

/* import */
extern ServerOptions options;

#ifdef WITH_AIXAUTHENTICATE
extern char *aixloginmsg;
#endif /* WITH_AIXAUTHENTICATE */

/*
 * convert ssh auth msg type into description
 */
static char *
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
	case SSH_CMSG_AUTH_TIS:
	case SSH_CMSG_AUTH_TIS_RESPONSE:
		return "challenge-response";
#if defined(KRB4) || defined(KRB5)
	case SSH_CMSG_AUTH_KERBEROS:
		return "kerberos";
#endif
	}
	snprintf(buf, sizeof buf, "bad-auth-msg-%d", type);
	return buf;
}

/*
 * read packets, try to authenticate the user and
 * return only if authentication is successful
 */
static void
do_authloop(Authctxt *authctxt)
{
	int authenticated = 0;
	u_int bits;
	RSA *client_host_key;
	BIGNUM *n;
	char *client_user, *password;
	char info[1024];
	u_int dlen;
	int plen, nlen, elen;
	u_int ulen;
	int type = 0;
	struct passwd *pw = authctxt->pw;

	debug("Attempting authentication for %s%.100s.",
	     authctxt->valid ? "" : "illegal user ", authctxt->user);

	/* If the user has no password, accept authentication immediately. */
	if (options.password_authentication &&
#if defined(KRB4) || defined(KRB5)
	    (!options.kerberos_authentication || options.kerberos_or_local_passwd) &&
#endif
#ifdef USE_PAM
	    auth_pam_password(pw, "")) {
#elif defined(HAVE_OSF_SIA)
	    0) {
#else
	    auth_password(authctxt, "")) {
#endif
		auth_log(authctxt, 1, "without authentication", "");
		return;
	}

	/* Indicate that authentication is needed. */
	packet_start(SSH_SMSG_FAILURE);
	packet_send();
	packet_write_wait();

	client_user = NULL;

	for (;;) {
		/* default to fail */
		authenticated = 0;

		info[0] = '\0';

		/* Get a packet from the client. */
		type = packet_read(&plen);

		/* Process the packet. */
		switch (type) {

#if defined(KRB4) || defined(KRB5)
		case SSH_CMSG_AUTH_KERBEROS:
			if (!options.kerberos_authentication) {
				verbose("Kerberos authentication disabled.");
			} else {
				char *kdata = packet_get_string(&dlen);
				
				packet_integrity_check(plen, 4 + dlen, type);
				
				if (kdata[0] == 4) { /* KRB_PROT_VERSION */
#ifdef KRB4
					KTEXT_ST tkt;
					
					tkt.length = dlen;
					if (tkt.length < MAX_KTXT_LEN)
						memcpy(tkt.dat, kdata, tkt.length);
					
					if (auth_krb4(authctxt, &tkt, &client_user)) {
						authenticated = 1;
						snprintf(info, sizeof(info),
						    " tktuser %.100s",
						    client_user);
					}
#endif /* KRB4 */
				} else {
#ifdef KRB5
					krb5_data tkt;
					tkt.length = dlen;
					tkt.data = kdata;
					
					if (auth_krb5(authctxt, &tkt, &client_user)) {
						authenticated = 1;
						snprintf(info, sizeof(info),
						    " tktuser %.100s",
						    client_user);
					}
#endif /* KRB5 */
				}
				xfree(kdata);
			}
			break;
#endif /* KRB4 || KRB5 */
			
#if defined(AFS) || defined(KRB5)
			/* XXX - punt on backward compatibility here. */
		case SSH_CMSG_HAVE_KERBEROS_TGT:
			packet_send_debug("Kerberos TGT passing disabled before authentication.");
			break;
#ifdef AFS
		case SSH_CMSG_HAVE_AFS_TOKEN:
			packet_send_debug("AFS token passing disabled before authentication.");
			break;
#endif /* AFS */
#endif /* AFS || KRB5 */
			
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

			/* Try to authenticate using /etc/hosts.equiv and .rhosts. */
			authenticated = auth_rhosts(pw, client_user);

			snprintf(info, sizeof info, " ruser %.100s", client_user);
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
				verbose("Warning: keysize mismatch for client_host_key: "
				    "actual %d, announced %d", BN_num_bits(client_host_key->n), bits);
			packet_integrity_check(plen, (4 + ulen) + 4 + elen + nlen, type);

			authenticated = auth_rhosts_rsa(pw, client_user, client_host_key);
			RSA_free(client_host_key);

			snprintf(info, sizeof info, " ruser %.100s", client_user);
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
#elif defined(HAVE_OSF_SIA)
			/* Do SIA auth with password */
			authenticated = auth_sia_password(authctxt->user, 
			    password);
#else /* !USE_PAM && !HAVE_OSF_SIA */
			/* Try authentication with the password. */
			authenticated = auth_password(authctxt, password);
#endif /* USE_PAM */

			memset(password, 0, strlen(password));
			xfree(password);
			break;

		case SSH_CMSG_AUTH_TIS:
			debug("rcvd SSH_CMSG_AUTH_TIS");
			if (options.challenge_response_authentication == 1) {
				char *challenge = get_challenge(authctxt);
				if (challenge != NULL) {
					debug("sending challenge '%s'", challenge);
					packet_start(SSH_SMSG_AUTH_TIS_CHALLENGE);
					packet_put_cstring(challenge);
					xfree(challenge);
					packet_send();
					packet_write_wait();
					continue;
				}
			}
			break;
		case SSH_CMSG_AUTH_TIS_RESPONSE:
			debug("rcvd SSH_CMSG_AUTH_TIS_RESPONSE");
			if (options.challenge_response_authentication == 1) {
				char *response = packet_get_string(&dlen);
				debug("got response '%s'", response);
				packet_integrity_check(plen, 4 + dlen, type);
				authenticated = verify_response(authctxt, response);
				memset(response, 'r', dlen);
				xfree(response);
			}
			break;

		default:
			/*
			 * Any unknown messages will be ignored (and failure
			 * returned) during authentication.
			 */
			log("Unknown message during authentication: type %d", type);
			break;
		}
#ifdef BSD_AUTH
		if (authctxt->as) {
			auth_close(authctxt->as);
			authctxt->as = NULL;
		}
#endif
		if (!authctxt->valid && authenticated)
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);

#ifdef HAVE_CYGWIN
		if (authenticated &&
		    !check_nt_auth(type == SSH_CMSG_AUTH_PASSWORD,pw->pw_uid)) {
			packet_disconnect("Authentication rejected for uid %d.",
			(int)pw->pw_uid);
			authenticated = 0;
		}
#else
		/* Special handling for root */
		if (authenticated && authctxt->pw->pw_uid == 0 &&
		    !auth_root_allowed(get_authname(type)))
			authenticated = 0;
#endif
#ifdef USE_PAM
		if (authenticated && !do_pam_account(pw->pw_name, client_user))
			authenticated = 0;
#endif

		/* Log before sending the reply */
		auth_log(authctxt, authenticated, get_authname(type), info);

		if (client_user != NULL) {
			xfree(client_user);
			client_user = NULL;
		}

		if (authenticated)
			return;

		if (authctxt->failures++ > AUTH_FAIL_MAX) {
#ifdef WITH_AIXAUTHENTICATE
			loginfailed(authctxt->user,
			    get_canonical_hostname(options.reverse_mapping_check),
			    "ssh");
#endif /* WITH_AIXAUTHENTICATE */
			packet_disconnect(AUTH_FAIL_MSG, authctxt->user);
		}

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
	Authctxt *authctxt;
	struct passwd *pw;
	int plen;
	u_int ulen;
	char *p, *user, *style = NULL;

	/* Get the name of the user that we wish to log in as. */
	packet_read_expect(&plen, SSH_CMSG_USER);

	/* Get the user name. */
	user = packet_get_string(&ulen);
	packet_integrity_check(plen, (4 + ulen), SSH_CMSG_USER);

	if ((style = strchr(user, ':')) != NULL)
		*style++ = '\0';

	/* XXX - SSH.com Kerberos v5 braindeath. */
	if ((p = strchr(user, '@')) != NULL)
		*p = '\0';
	
	authctxt = authctxt_new();
	authctxt->user = user;
	authctxt->style = style;

	/* Verify that the user is a valid user. */
	pw = getpwnam(user);
	if (pw && allowed_user(pw)) {
		authctxt->valid = 1;
		pw = pwcopy(pw);
	} else {
		debug("do_authentication: illegal user %s", user);
		pw = NULL;
	}
	authctxt->pw = pw;

	setproctitle("%s", pw ? user : "unknown");

#ifdef USE_PAM
	if (pw)
		start_pam(user);
#endif

	/*
	 * If we are not running as root, the user must have the same uid as
	 * the server. (Unless you are running Windows)
	 */
#ifndef HAVE_CYGWIN
	if (getuid() != 0 && pw && pw->pw_uid != getuid())
		packet_disconnect("Cannot change user when server not running as root.");
#endif

	/*
	 * Loop until the user has been authenticated or the connection is
	 * closed, do_authloop() returns only if authentication is successful
	 */
	do_authloop(authctxt);

	/* The user has been authenticated and accepted. */
	packet_start(SSH_SMSG_SUCCESS);
	packet_send();
	packet_write_wait();

#ifdef WITH_AIXAUTHENTICATE
	/* We don't have a pty yet, so just label the line as "ssh" */
	if (loginsuccess(authctxt->user,
	    get_canonical_hostname(options.reverse_mapping_check),
	    "ssh", &aixloginmsg) < 0)
		aixloginmsg = NULL;
#endif /* WITH_AIXAUTHENTICATE */

	/* Perform session preparation. */
	do_authenticated(authctxt);
}
