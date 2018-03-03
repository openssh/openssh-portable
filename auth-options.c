/* $OpenBSD: auth-options.c,v 1.75 2018/03/03 03:06:02 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 2018 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>

#include <netdb.h>
#include <pwd.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>

#include "openbsd-compat/sys-queue.h"

#include "key.h"	/* XXX for typedef */
#include "buffer.h"	/* XXX for typedef */
#include "xmalloc.h"
#include "match.h"
#include "ssherr.h"
#include "ssh2.h"
#include "log.h"
#include "canohost.h"
#include "packet.h"
#include "sshbuf.h"
#include "misc.h"
#include "channels.h"
#include "servconf.h"
#include "sshkey.h"
#include "auth-options.h"
#include "hostfile.h"
#include "auth.h"

/* Flags set authorized_keys flags */
int no_port_forwarding_flag = 0;
int no_agent_forwarding_flag = 0;
int no_x11_forwarding_flag = 0;
int no_pty_flag = 0;
int no_user_rc = 0;
int key_is_cert_authority = 0;

/* "command=" option. */
char *forced_command = NULL;

/* "environment=" options. */
struct envstring *custom_environment = NULL;

/* "tunnel=" option. */
int forced_tun_device = -1;

/* "principals=" option. */
char *authorized_principals = NULL;

extern ServerOptions options;

/* XXX refactor to be stateless */

void
auth_clear_options(void)
{
	struct ssh *ssh = active_state;		/* XXX */

	no_agent_forwarding_flag = 0;
	no_port_forwarding_flag = 0;
	no_pty_flag = 0;
	no_x11_forwarding_flag = 0;
	no_user_rc = 0;
	key_is_cert_authority = 0;
	while (custom_environment) {
		struct envstring *ce = custom_environment;
		custom_environment = ce->next;
		free(ce->s);
		free(ce);
	}
	free(forced_command);
	forced_command = NULL;
	free(authorized_principals);
	authorized_principals = NULL;
	forced_tun_device = -1;
	channel_clear_permitted_opens(ssh);
}

/*
 * Match flag 'opt' in *optsp, and if allow_negate is set then also match
 * 'no-opt'. Returns -1 if option not matched, 1 if option matches or 0
 * if negated option matches. 
 * If the option or negated option matches, then *optsp is updated to
 * point to the first character after the option and, if 'msg' is not NULL
 * then a message based on it added via auth_debug_add().
 */
static int
match_flag(const char *opt, int allow_negate, char **optsp, const char *msg)
{
	size_t opt_len = strlen(opt);
	char *opts = *optsp;
	int negate = 0;

	if (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	if (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		if (msg != NULL) {
			auth_debug_add("%s %s.", msg,
			    negate ? "disabled" : "enabled");
		}
		return negate ? 0 : 1;
	}
	return -1;
}

/*
 * return 1 if access is granted, 0 if not.
 * side effect: sets key option flags
 * XXX remove side effects; fill structure instead.
 */
int
auth_parse_options(struct passwd *pw, char *opts, const char *file,
    u_long linenum)
{
	struct ssh *ssh = active_state;		/* XXX */
	const char *cp;
	int i, r;

	/* reset options */
	auth_clear_options();

	if (!opts)
		return 1;

	while (*opts && *opts != ' ' && *opts != '\t') {
		if ((r = match_flag("cert-authority", 0, &opts, NULL)) != -1) {
			key_is_cert_authority = r;
			goto next_option;
		}
		if ((r = match_flag("restrict", 0, &opts, NULL)) != -1) {
			auth_debug_add("Key is restricted.");
			no_port_forwarding_flag = 1;
			no_agent_forwarding_flag = 1;
			no_x11_forwarding_flag = 1;
			no_pty_flag = 1;
			no_user_rc = 1;
			goto next_option;
		}
		if ((r = match_flag("port-forwarding", 1, &opts,
		    "Port forwarding")) != -1) {
			no_port_forwarding_flag = r != 1;
			goto next_option;
		}
		if ((r = match_flag("agent-forwarding", 1, &opts,
		    "Agent forwarding")) != -1) {
			no_agent_forwarding_flag = r != 1;
			goto next_option;
		}
		if ((r = match_flag("x11-forwarding", 1, &opts,
		    "X11 forwarding")) != -1) {
			no_x11_forwarding_flag = r != 1;
			goto next_option;
		}
		if ((r = match_flag("pty", 1, &opts,
		    "PTY allocation")) != -1) {
			no_pty_flag = r != 1;
			goto next_option;
		}
		if ((r = match_flag("user-rc", 1, &opts,
		    "User rc execution")) != -1) {
			no_user_rc = r != 1;
			goto next_option;
		}
		cp = "command=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			opts += strlen(cp);
			free(forced_command);
			forced_command = xmalloc(strlen(opts) + 1);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				if (*opts == '\\' && opts[1] == '"') {
					opts += 2;
					forced_command[i++] = '"';
					continue;
				}
				forced_command[i++] = *opts++;
			}
			if (!*opts) {
				debug("%.100s, line %lu: missing end quote",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: missing end quote",
				    file, linenum);
				free(forced_command);
				forced_command = NULL;
				goto bad_option;
			}
			forced_command[i] = '\0';
			auth_debug_add("Forced command.");
			opts++;
			goto next_option;
		}
		cp = "principals=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			opts += strlen(cp);
			free(authorized_principals);
			authorized_principals = xmalloc(strlen(opts) + 1);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				if (*opts == '\\' && opts[1] == '"') {
					opts += 2;
					authorized_principals[i++] = '"';
					continue;
				}
				authorized_principals[i++] = *opts++;
			}
			if (!*opts) {
				debug("%.100s, line %lu: missing end quote",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: missing end quote",
				    file, linenum);
				free(authorized_principals);
				authorized_principals = NULL;
				goto bad_option;
			}
			authorized_principals[i] = '\0';
			auth_debug_add("principals: %.900s",
			    authorized_principals);
			opts++;
			goto next_option;
		}
		cp = "environment=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			char *s;
			struct envstring *new_envstring;

			opts += strlen(cp);
			s = xmalloc(strlen(opts) + 1);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				if (*opts == '\\' && opts[1] == '"') {
					opts += 2;
					s[i++] = '"';
					continue;
				}
				s[i++] = *opts++;
			}
			if (!*opts) {
				debug("%.100s, line %lu: missing end quote",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: missing end quote",
				    file, linenum);
				free(s);
				goto bad_option;
			}
			s[i] = '\0';
			opts++;
			if (options.permit_user_env) {
				auth_debug_add("Adding to environment: "
				    "%.900s", s);
				debug("Adding to environment: %.900s", s);
				new_envstring = xcalloc(1,
				    sizeof(*new_envstring));
				new_envstring->s = s;
				new_envstring->next = custom_environment;
				custom_environment = new_envstring;
				s = NULL;
			}
			free(s);
			goto next_option;
		}
		cp = "from=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			const char *remote_ip = ssh_remote_ipaddr(ssh);
			const char *remote_host = auth_get_canonical_hostname(
			    ssh, options.use_dns);
			char *patterns = xmalloc(strlen(opts) + 1);

			opts += strlen(cp);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				if (*opts == '\\' && opts[1] == '"') {
					opts += 2;
					patterns[i++] = '"';
					continue;
				}
				patterns[i++] = *opts++;
			}
			if (!*opts) {
				debug("%.100s, line %lu: missing end quote",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: missing end quote",
				    file, linenum);
				free(patterns);
				goto bad_option;
			}
			patterns[i] = '\0';
			opts++;
			switch (match_host_and_ip(remote_host, remote_ip,
			    patterns)) {
			case 1:
				free(patterns);
				/* Host name matches. */
				goto next_option;
			case -1:
				debug("%.100s, line %lu: invalid criteria",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: "
				    "invalid criteria", file, linenum);
				/* FALLTHROUGH */
			case 0:
				free(patterns);
				logit("Authentication tried for %.100s with "
				    "correct key but not from a permitted "
				    "host (host=%.200s, ip=%.200s).",
				    pw->pw_name, remote_host, remote_ip);
				auth_debug_add("Your host '%.200s' is not "
				    "permitted to use this key for login.",
				    remote_host);
				break;
			}
			/* deny access */
			return 0;
		}
		cp = "permitopen=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			char *host, *p;
			int port;
			char *patterns = xmalloc(strlen(opts) + 1);

			opts += strlen(cp);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				if (*opts == '\\' && opts[1] == '"') {
					opts += 2;
					patterns[i++] = '"';
					continue;
				}
				patterns[i++] = *opts++;
			}
			if (!*opts) {
				debug("%.100s, line %lu: missing end quote",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: missing "
				    "end quote", file, linenum);
				free(patterns);
				goto bad_option;
			}
			patterns[i] = '\0';
			opts++;
			p = patterns;
			/* XXX - add streamlocal support */
			host = hpdelim(&p);
			if (host == NULL || strlen(host) >= NI_MAXHOST) {
				debug("%.100s, line %lu: Bad permitopen "
				    "specification <%.100s>", file, linenum,
				    patterns);
				auth_debug_add("%.100s, line %lu: "
				    "Bad permitopen specification", file,
				    linenum);
				free(patterns);
				goto bad_option;
			}
			host = cleanhostname(host);
			if (p == NULL || (port = permitopen_port(p)) < 0) {
				debug("%.100s, line %lu: Bad permitopen port "
				    "<%.100s>", file, linenum, p ? p : "");
				auth_debug_add("%.100s, line %lu: "
				    "Bad permitopen port", file, linenum);
				free(patterns);
				goto bad_option;
			}
			if ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0)
				channel_add_permitted_opens(ssh, host, port);
			free(patterns);
			goto next_option;
		}
		cp = "tunnel=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			char *tun = NULL;
			opts += strlen(cp);
			tun = xmalloc(strlen(opts) + 1);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				tun[i++] = *opts++;
			}
			if (!*opts) {
				debug("%.100s, line %lu: missing end quote",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: missing end quote",
				    file, linenum);
				free(tun);
				forced_tun_device = -1;
				goto bad_option;
			}
			tun[i] = '\0';
			forced_tun_device = a2tun(tun, NULL);
			free(tun);
			if (forced_tun_device == SSH_TUNID_ERR) {
				debug("%.100s, line %lu: invalid tun device",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: invalid tun device",
				    file, linenum);
				forced_tun_device = -1;
				goto bad_option;
			}
			auth_debug_add("Forced tun device: %d", forced_tun_device);
			opts++;
			goto next_option;
		}
next_option:
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		if (!*opts)
			fatal("Bugs in auth-options.c option processing.");
		if (*opts == ' ' || *opts == '\t')
			break;		/* End of options. */
		if (*opts != ',')
			goto bad_option;
		opts++;
		/* Process the next option. */
	}

	/* grant access */
	return 1;

bad_option:
	logit("Bad options in %.100s file, line %lu: %.50s",
	    file, linenum, opts);
	auth_debug_add("Bad options in %.100s file, line %lu: %.50s",
	    file, linenum, opts);

	/* deny access */
	return 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
static int
parse_option_list(struct sshbuf *oblob, struct passwd *pw,
    u_int which, int crit,
    int *cert_no_port_forwarding_flag,
    int *cert_no_agent_forwarding_flag,
    int *cert_no_x11_forwarding_flag,
    int *cert_no_pty_flag,
    int *cert_no_user_rc,
    char **cert_forced_command,
    int *cert_source_address_done)
{
	struct ssh *ssh = active_state;		/* XXX */
	char *command, *allowed;
	const char *remote_ip;
	char *name = NULL;
	struct sshbuf *c = NULL, *data = NULL;
	int r, ret = -1, result, found;

	if ((c = sshbuf_fromb(oblob)) == NULL) {
		error("%s: sshbuf_fromb failed", __func__);
		goto out;
	}

	while (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = NULL;
		if ((r = sshbuf_get_cstring(c, &name, NULL)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error("Unable to parse certificate options: %s",
			    ssh_err(r));
			goto out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		if ((which & OPTIONS_EXTENSIONS) != 0) {
			if (strcmp(name, "permit-X11-forwarding") == 0) {
				*cert_no_x11_forwarding_flag = 0;
				found = 1;
			} else if (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				*cert_no_agent_forwarding_flag = 0;
				found = 1;
			} else if (strcmp(name,
			    "permit-port-forwarding") == 0) {
				*cert_no_port_forwarding_flag = 0;
				found = 1;
			} else if (strcmp(name, "permit-pty") == 0) {
				*cert_no_pty_flag = 0;
				found = 1;
			} else if (strcmp(name, "permit-user-rc") == 0) {
				*cert_no_user_rc = 0;
				found = 1;
			}
		}
		if (!found && (which & OPTIONS_CRITICAL) != 0) {
			if (strcmp(name, "force-command") == 0) {
				if ((r = sshbuf_get_cstring(data, &command,
				    NULL)) != 0) {
					error("Unable to parse \"%s\" "
					    "section: %s", name, ssh_err(r));
					goto out;
				}
				if (*cert_forced_command != NULL) {
					error("Certificate has multiple "
					    "force-command options");
					free(command);
					goto out;
				}
				*cert_forced_command = command;
				found = 1;
			}
			if (strcmp(name, "source-address") == 0) {
				if ((r = sshbuf_get_cstring(data, &allowed,
				    NULL)) != 0) {
					error("Unable to parse \"%s\" "
					    "section: %s", name, ssh_err(r));
					goto out;
				}
				if ((*cert_source_address_done)++) {
					error("Certificate has multiple "
					    "source-address options");
					free(allowed);
					goto out;
				}
				remote_ip = ssh_remote_ipaddr(ssh);
				result = addr_match_cidr_list(remote_ip,
				    allowed);
				free(allowed);
				switch (result) {
				case 1:
					/* accepted */
					break;
				case 0:
					/* no match */
					logit("Authentication tried for %.100s "
					    "with valid certificate but not "
					    "from a permitted host "
					    "(ip=%.200s).", pw->pw_name,
					    remote_ip);
					auth_debug_add("Your address '%.200s' "
					    "is not permitted to use this "
					    "certificate for login.",
					    remote_ip);
					goto out;
				case -1:
				default:
					error("Certificate source-address "
					    "contents invalid");
					goto out;
				}
				found = 1;
			}
		}

		if (!found) {
			if (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				goto out;
			} else {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} else if (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			goto out;
		}
		free(name);
		name = NULL;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	if (ret != 0 &&
	    cert_forced_command != NULL &&
	    *cert_forced_command != NULL) {
		free(*cert_forced_command);
		*cert_forced_command = NULL;
	}
	free(name);
	sshbuf_free(data);
	sshbuf_free(c);
	return ret;
}

/*
 * Set options from critical certificate options. These supersede user key
 * options so this must be called after auth_parse_options().
 */
int
auth_cert_options(struct sshkey *k, struct passwd *pw, const char **reason)
{
	int cert_no_port_forwarding_flag = 1;
	int cert_no_agent_forwarding_flag = 1;
	int cert_no_x11_forwarding_flag = 1;
	int cert_no_pty_flag = 1;
	int cert_no_user_rc = 1;
	char *cert_forced_command = NULL;
	int cert_source_address_done = 0;

	*reason = "invalid certificate options";

	/* Separate options and extensions for v01 certs */
	if (parse_option_list(k->cert->critical, pw,
	    OPTIONS_CRITICAL, 1, NULL, NULL, NULL, NULL, NULL,
	    &cert_forced_command,
	    &cert_source_address_done) == -1)
		return -1;
	if (parse_option_list(k->cert->extensions, pw,
	    OPTIONS_EXTENSIONS, 0,
	    &cert_no_port_forwarding_flag,
	    &cert_no_agent_forwarding_flag,
	    &cert_no_x11_forwarding_flag,
	    &cert_no_pty_flag,
	    &cert_no_user_rc,
	    NULL, NULL) == -1)
		return -1;

	no_port_forwarding_flag |= cert_no_port_forwarding_flag;
	no_agent_forwarding_flag |= cert_no_agent_forwarding_flag;
	no_x11_forwarding_flag |= cert_no_x11_forwarding_flag;
	no_pty_flag |= cert_no_pty_flag;
	no_user_rc |= cert_no_user_rc;
	/*
	 * Only permit both CA and key option forced-command if they match.
	 * Otherwise refuse the certificate.
	 */
	if (cert_forced_command != NULL && forced_command != NULL) {
		if (strcmp(forced_command, cert_forced_command) == 0) {
			free(forced_command);
			forced_command = cert_forced_command;
		} else {
			*reason = "certificate and key options forced command "
			    "do not match";
			free(cert_forced_command);
			return -1;
		}
	} else if (cert_forced_command != NULL)
		forced_command = cert_forced_command;
	/* success */
	*reason = NULL;
	return 0;
}

/*
 * authorized_keys options processing.
 */

/*
 * Match flag 'opt' in *optsp, and if allow_negate is set then also match
 * 'no-opt'. Returns -1 if option not matched, 1 if option matches or 0
 * if negated option matches.
 * If the option or negated option matches, then *optsp is updated to
 * point to the first character after the option.
 */
static int
opt_flag(const char *opt, int allow_negate, const char **optsp)
{
	size_t opt_len = strlen(opt);
	const char *opts = *optsp;
	int negate = 0;

	if (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	if (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		return negate ? 0 : 1;
	}
	return -1;
}

static char *
opt_dequote(const char **sp, const char **errstrp)
{
	const char *s = *sp;
	char *ret;
	size_t i;

	*errstrp = NULL;
	if (*s != '"') {
		*errstrp = "missing start quote";
		return NULL;
	}
	s++;
	if ((ret = malloc(strlen((s)) + 1)) == NULL) {
		*errstrp = "memory allocation failed";
		return NULL;
	}
	for (i = 0; *s != '\0' && *s != '"';) {
		if (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	if (*s == '\0') {
		*errstrp = "missing end quote";
		free(ret);
		return NULL;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	return ret;
}

static int
opt_match(const char **opts, const char *term)
{
	if (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		return 1;
	}
	return 0;
}

static int
dup_strings(char ***dstp, size_t *ndstp, char **src, size_t nsrc)
{
	char **dst;
	size_t i, j;

	*dstp = NULL;
	*ndstp = 0;
	if (nsrc == 0)
		return 0;

	if ((dst = calloc(nsrc, sizeof(*src))) == NULL)
		return -1;
	for (i = 0; i < nsrc; i++) {
		if ((dst[i] = strdup(src[i])) == NULL) {
			for (j = 0; j < i; j++)
				free(dst[j]);
			free(dst);
			return -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	return 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
static int
cert_option_list(struct sshauthopt *opts, struct sshbuf *oblob,
    u_int which, int crit)
{
	char *command, *allowed;
	char *name = NULL;
	struct sshbuf *c = NULL, *data = NULL;
	int r, ret = -1, found;

	if ((c = sshbuf_fromb(oblob)) == NULL) {
		error("%s: sshbuf_fromb failed", __func__);
		goto out;
	}

	while (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = NULL;
		if ((r = sshbuf_get_cstring(c, &name, NULL)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error("Unable to parse certificate options: %s",
			    ssh_err(r));
			goto out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		if ((which & OPTIONS_EXTENSIONS) != 0) {
			if (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} else if (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} else if (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} else if (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} else if (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		if (!found && (which & OPTIONS_CRITICAL) != 0) {
			if (strcmp(name, "force-command") == 0) {
				if ((r = sshbuf_get_cstring(data, &command,
				    NULL)) != 0) {
					error("Unable to parse \"%s\" "
					    "section: %s", name, ssh_err(r));
					goto out;
				}
				if (opts->force_command != NULL) {
					error("Certificate has multiple "
					    "force-command options");
					free(command);
					goto out;
				}
				opts->force_command = command;
				found = 1;
			}
			if (strcmp(name, "source-address") == 0) {
				if ((r = sshbuf_get_cstring(data, &allowed,
				    NULL)) != 0) {
					error("Unable to parse \"%s\" "
					    "section: %s", name, ssh_err(r));
					goto out;
				}
				if (opts->required_from_host_cert != NULL) {
					error("Certificate has multiple "
					    "source-address options");
					free(allowed);
					goto out;
				}
				/* Check syntax */
				if (addr_match_cidr_list(NULL, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					goto out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		if (!found) {
			if (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				goto out;
			} else {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} else if (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			goto out;
		}
		free(name);
		name = NULL;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	free(name);
	sshbuf_free(data);
	sshbuf_free(c);
	return ret;
}

struct sshauthopt *
sshauthopt_new(void)
{
	struct sshauthopt *ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;
	ret->force_tun_device = -1;
	return ret;
}

void
sshauthopt_free(struct sshauthopt *opts)
{
	size_t i;

	if (opts == NULL)
		return;

	free(opts->cert_principals);
	free(opts->force_command);
	free(opts->required_from_host_cert);
	free(opts->required_from_host_keys);

	for (i = 0; i < opts->nenv; i++)
		free(opts->env[i]);
	free(opts->env);

	for (i = 0; i < opts->npermitopen; i++)
		free(opts->permitopen[i]);
	free(opts->permitopen);

	explicit_bzero(opts, sizeof(*opts));
	free(opts);
}

struct sshauthopt *
sshauthopt_new_with_keys_defaults(void)
{
	struct sshauthopt *ret = NULL;

	if ((ret = sshauthopt_new()) == NULL)
		return NULL;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	return ret;
}

struct sshauthopt *
sshauthopt_parse(const char *opts, const char **errstrp)
{
	char **oarray, *opt, *cp, *tmp, *host;
	int r;
	struct sshauthopt *ret = NULL;
	const char *errstr = "unknown error";

	if (errstrp != NULL)
		*errstrp = NULL;
	if ((ret = sshauthopt_new_with_keys_defaults()) == NULL)
		goto alloc_fail;

	if (opts == NULL)
		return ret;

	while (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		if ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} else if ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} else if ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} else if ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} else if ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} else if ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} else if ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} else if (opt_match(&opts, "command")) {
			if (ret->force_command != NULL) {
				errstr = "multiple \"command\" clauses";
				goto fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			if (ret->force_command == NULL)
				goto fail;
		} else if (opt_match(&opts, "principals")) {
			if (ret->cert_principals != NULL) {
				errstr = "multiple \"principals\" clauses";
				goto fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			if (ret->cert_principals == NULL)
				goto fail;
		} else if (opt_match(&opts, "from")) {
			if (ret->required_from_host_keys != NULL) {
				errstr = "multiple \"from\" clauses";
				goto fail;
			}
			ret->required_from_host_keys = opt_dequote(&opts,
			    &errstr);
			if (ret->required_from_host_keys == NULL)
				goto fail;
		} else if (opt_match(&opts, "environment")) {
			if (ret->nenv > INT_MAX) {
				errstr = "too many environment strings";
				goto fail;
			}
			if ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			/* env name must be alphanumeric and followed by '=' */
			if ((tmp = strchr(opt, '=')) == NULL) {
				free(opt);
				errstr = "invalid environment string";
				goto fail;
			}
			for (cp = opt; cp < tmp; cp++) {
				if (!isalnum((u_char)*cp)) {
					free(opt);
					errstr = "invalid environment string";
					goto fail;
				}
			}
			/* Append it. */
			oarray = ret->env;
			if ((ret->env = recallocarray(ret->env, ret->nenv,
			    ret->nenv + 1, sizeof(*ret->env))) == NULL) {
				free(opt);
				ret->env = oarray; /* put it back for cleanup */
				goto alloc_fail;
			}
			ret->env[ret->nenv++] = opt;
		} else if (opt_match(&opts, "permitopen")) {
			if (ret->npermitopen > INT_MAX) {
				errstr = "too many permitopens";
				goto fail;
			}
			if ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			if ((tmp = strdup(opt)) == NULL) {
				free(opt);
				goto alloc_fail;
			}
			cp = tmp;
			/* validate syntax of permitopen before recording it. */
			host = hpdelim(&cp);
			if (host == NULL || strlen(host) >= NI_MAXHOST) {
				free(tmp);
				free(opt);
				errstr = "invalid permitopen hostname";
				goto fail;
			}
			/*
			 * don't want to use permitopen_port to avoid
			 * dependency on channels.[ch] here.
			 */
			if (cp == NULL ||
			    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
				free(tmp);
				free(opt);
				errstr = "invalid permitopen port";
				goto fail;
			}
			/* XXX - add streamlocal support */
			free(tmp);
			/* Record it */
			oarray = ret->permitopen;
			if ((ret->permitopen = recallocarray(ret->permitopen,
			    ret->npermitopen, ret->npermitopen + 1,
			    sizeof(*ret->permitopen))) == NULL) {
				free(opt);
				ret->permitopen = oarray;
				goto alloc_fail;
			}
			ret->permitopen[ret->npermitopen++] = opt;
		} else if (opt_match(&opts, "tunnel")) {
			if ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			ret->force_tun_device = a2tun(opt, NULL);
			free(opt);
			if (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				goto fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		if (*opts == '\0' || *opts == ' ' || *opts == '\t')
			break;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		if (*opts != ',') {
			errstr = "unknown key option";
			goto fail;
		}
		opts++;
		if (*opts == '\0') {
			errstr = "unexpected end-of-options";
			goto fail;
		}
	}

	/* success */
	if (errstrp != NULL)
		*errstrp = NULL;
	return ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	if (errstrp != NULL)
		*errstrp = errstr;
	return NULL;
}

struct sshauthopt *
sshauthopt_from_cert(struct sshkey *k)
{
	struct sshauthopt *ret;

	if (k == NULL || !sshkey_type_is_cert(k->type) || k->cert == NULL ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		return NULL;

	if ((ret = sshauthopt_new()) == NULL)
		return NULL;

	/* Handle options and critical extensions separately */
	if (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		return NULL;
	}
	if (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		return NULL;
	}
	/* success */
	return ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
struct sshauthopt *
sshauthopt_merge(const struct sshauthopt *primary,
    const struct sshauthopt *additional, const char **errstrp)
{
	struct sshauthopt *ret;
	const char *errstr = "internal error";
	const char *tmp;

	if (errstrp != NULL)
		*errstrp = NULL;

	if ((ret = sshauthopt_new()) == NULL)
		goto alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	if (tmp == NULL)
		tmp = additional->required_from_host_cert;
	if (tmp != NULL && (ret->required_from_host_cert = strdup(tmp)) == NULL)
		goto alloc_fail;
	tmp = primary->required_from_host_keys;
	if (tmp == NULL)
		tmp = additional->required_from_host_keys;
	if (tmp != NULL && (ret->required_from_host_keys = strdup(tmp)) == NULL)
		goto alloc_fail;

	/* force_tun_device, permitopen and environment prefer the primary. */
	ret->force_tun_device = primary->force_tun_device;
	if (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	if (primary->nenv > 0) {
		if (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			goto alloc_fail;
	} else if (additional->nenv) {
		if (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			goto alloc_fail;
	}
	if (primary->npermitopen > 0) {
		if (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			goto alloc_fail;
	} else if (additional->npermitopen > 0) {
		if (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			goto alloc_fail;
	}

	/* Flags are logical-AND (i.e. must be set in both for permission) */
#define OPTFLAG(x) ret->x = (primary->x == 1) && (additional->x == 1)
	OPTFLAG(permit_port_forwarding_flag);
	OPTFLAG(permit_agent_forwarding_flag);
	OPTFLAG(permit_x11_forwarding_flag);
	OPTFLAG(permit_pty_flag);
	OPTFLAG(permit_user_rc);
#undef OPTFLAG

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	if (primary->force_command != NULL &&
	    additional->force_command != NULL) {
		if (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			if (ret->force_command == NULL)
				goto alloc_fail;
		} else {
			errstr = "forced command options do not match";
			goto fail;
		}
	} else if (primary->force_command != NULL) {
		if ((ret->force_command = strdup(
		    primary->force_command)) == NULL)
			goto alloc_fail;
	} else if (additional->force_command != NULL) {
		if ((ret->force_command = strdup(
		    additional->force_command)) == NULL)
			goto alloc_fail;
	}
	/* success */
	if (errstrp != NULL)
		*errstrp = NULL;
	return ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	if (errstrp != NULL)
		*errstrp = errstr;
	sshauthopt_free(ret);
	return NULL;
}

/*
 * Copy options
 */
struct sshauthopt *
sshauthopt_copy(const struct sshauthopt *orig)
{
	struct sshauthopt *ret;

	if ((ret = sshauthopt_new()) == NULL)
		return NULL;

#define OPTSCALAR(x) ret->x = orig->x
	OPTSCALAR(permit_port_forwarding_flag);
	OPTSCALAR(permit_agent_forwarding_flag);
	OPTSCALAR(permit_x11_forwarding_flag);
	OPTSCALAR(permit_pty_flag);
	OPTSCALAR(permit_user_rc);
	OPTSCALAR(restricted);
	OPTSCALAR(cert_authority);
	OPTSCALAR(force_tun_device);
#undef OPTSCALAR
#define OPTSTRING(x) \
	do { \
		if (orig->x != NULL && (ret->x = strdup(orig->x)) == NULL) { \
			sshauthopt_free(ret); \
			return NULL; \
		} \
	} while (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_keys);
#undef OPTSTRING

	if (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0) {
		sshauthopt_free(ret);
		return NULL;
	}
	return ret;
}

static int
serialise_array(struct sshbuf *m, char **a, size_t n)
{
	struct sshbuf *b;
	size_t i;
	int r;

	if (n > INT_MAX)
		return SSH_ERR_INTERNAL_ERROR;

	if ((b = sshbuf_new()) == NULL) {
		return SSH_ERR_ALLOC_FAIL;
	}
	for (i = 0; i < n; i++) {
		if ((r = sshbuf_put_cstring(b, a[i])) != 0) {
			sshbuf_free(b);
			return r;
		}
	}
	if ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0) {
		sshbuf_free(b);
		return r;
	}
	/* success */
	return 0;
}

static int
deserialise_array(struct sshbuf *m, char ***ap, size_t *np)
{
	char **a = NULL;
	size_t i, n = 0;
	struct sshbuf *b = NULL;
	u_int tmp;
	int r = SSH_ERR_INTERNAL_ERROR;

	if ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		goto out;
	if (tmp > INT_MAX) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	n = tmp;
	if (n > 0 && (a = calloc(n, sizeof(*a))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	for (i = 0; i < n; i++) {
		if ((r = sshbuf_get_cstring(b, &a[i], NULL)) != 0)
			goto out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = NULL;
	*np = n;
	n = 0;
 out:
	for (i = 0; i < n; i++)
		free(a[i]);
	free(a);
	sshbuf_free(b);
	return r;
}

static int
serialise_nullable_string(struct sshbuf *m, const char *s)
{
	int r;

	if ((r = sshbuf_put_u8(m, s == NULL)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		return r;
	return 0;
}

static int
deserialise_nullable_string(struct sshbuf *m, char **sp)
{
	int r;
	u_char flag;

	*sp = NULL;
	if ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? NULL : sp, NULL)) != 0)
		return r;
	return 0;
}

int
sshauthopt_serialise(const struct sshauthopt *opts, struct sshbuf *m,
    int untrusted)
{
	int r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	if ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0)
		return r;

	/* tunnel number can be negative to indicate "unset" */
	if ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		return r;

	/* String options; these may be NULL */
	if ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? NULL : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	     untrusted ? NULL : opts->required_from_host_keys)) != 0)
		return r;

	/* Array options */
	if ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0)
		return r;

	/* success */
	return 0;
}

int
sshauthopt_deserialise(struct sshbuf *m, struct sshauthopt **optsp)
{
	struct sshauthopt *opts = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	if ((opts = calloc(1, sizeof(*opts))) == NULL)
		return SSH_ERR_ALLOC_FAIL;

#define OPT_FLAG(x) \
	do { \
		if ((r = sshbuf_get_u8(m, &f)) != 0) \
			goto out; \
		opts->x = f; \
	} while (0)
	OPT_FLAG(permit_port_forwarding_flag);
	OPT_FLAG(permit_agent_forwarding_flag);
	OPT_FLAG(permit_x11_forwarding_flag);
	OPT_FLAG(permit_pty_flag);
	OPT_FLAG(permit_user_rc);
	OPT_FLAG(restricted);
	OPT_FLAG(cert_authority);
#undef OPT_FLAG

	/* tunnel number can be negative to indicate "unset" */
	if ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		goto out;
	opts->force_tun_device = f ? -1 : (int)tmp;

	/* String options may be NULL */
	if ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_keys)) != 0)
		goto out;

	/* Array options */
	if ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0)
		goto out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = NULL;
 out:
	sshauthopt_free(opts);
	return r;
}
