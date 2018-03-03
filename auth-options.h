/* $OpenBSD: auth-options.h,v 1.24 2018/03/03 03:06:02 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef AUTH_OPTIONS_H
#define AUTH_OPTIONS_H

struct passwd;
struct sshkey;

/* Linked list of custom environment strings */
struct envstring {
	struct envstring *next;
	char   *s;
};

/* Flags that may be set in authorized_keys options. */
extern int no_port_forwarding_flag;
extern int no_agent_forwarding_flag;
extern int no_x11_forwarding_flag;
extern int no_pty_flag;
extern int no_user_rc;
extern char *forced_command;
extern struct envstring *custom_environment;
extern int forced_tun_device;
extern int key_is_cert_authority;
extern char *authorized_principals;

int	auth_parse_options(struct passwd *, char *, const char *, u_long);
void	auth_clear_options(void);
int	auth_cert_options(struct sshkey *, struct passwd *, const char **);

/* authorized_keys options handling */

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
struct sshauthopt {
	/* Feature flags */
	int permit_port_forwarding_flag;
	int permit_agent_forwarding_flag;
	int permit_x11_forwarding_flag;
	int permit_pty_flag;
	int permit_user_rc;

	/* "restrict" keyword was invoked */
	int restricted;

	/* Certificate-related options */
	int cert_authority;
	char *cert_principals;

	int force_tun_device;
	char *force_command;

	/* Custom environment */
	size_t nenv;
	char **env;

	/* Permitted port forwardings */
	size_t npermitopen;
	char **permitopen;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	char *required_from_host_cert;
	char *required_from_host_keys;
};

struct sshauthopt *sshauthopt_new(void);
struct sshauthopt *sshauthopt_new_with_keys_defaults(void);
void sshauthopt_free(struct sshauthopt *opts);
struct sshauthopt *sshauthopt_copy(const struct sshauthopt *orig);
int sshauthopt_serialise(const struct sshauthopt *opts, struct sshbuf *m, int);
int sshauthopt_deserialise(struct sshbuf *m, struct sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
struct sshauthopt *sshauthopt_parse(const char *s, const char **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
struct sshauthopt *sshauthopt_from_cert(struct sshkey *k);

/*
 * Merge key options.
 */
struct sshauthopt *sshauthopt_merge(const struct sshauthopt *primary,
    const struct sshauthopt *additional, const char **errstrp);

#endif
