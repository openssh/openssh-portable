/* $OpenBSD: auth2.c,v 1.135 2015/01/19 20:07:45 markus Exp $ */
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
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "atomicio.h"
#include "xmalloc.h"
#include "ssh2.h"
#include "packet.h"
#include "log.h"
#include "buffer.h"
#include "misc.h"
#include "servconf.h"
#include "compat.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "dispatch.h"
#include "pathnames.h"
#include "buffer.h"

#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"

/* import */
extern ServerOptions options;
extern u_char *session_id2;
extern u_int session_id2_len;
extern Buffer loginmsg;

/* methods */

extern Authmethod method_none;
extern Authmethod method_pubkey;
extern Authmethod method_passwd;
extern Authmethod method_kbdint;
extern Authmethod method_hostbased;
#ifdef GSSAPI
extern Authmethod method_gssapi;
#endif

Authmethod *authmethods[] = {
	&method_none,
	&method_pubkey,
#ifdef GSSAPI
	&method_gssapi,
#endif
	&method_passwd,
	&method_kbdint,
	&method_hostbased,
	NULL
};

/* protocol */

static int input_service_request(int, u_int32_t, void *);
static int input_userauth_request(int, u_int32_t, void *);

/* helper */
static Authmethod *authmethod_lookup(Authctxt *, const char *);
static char *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
static int list_starts_with(const char *, const char *, const char *);

char *
auth2_read_banner(void)
{
	struct stat st;
	char *banner = NULL;
	size_t len, n;
	int fd;

	if ((fd = open(options.banner, O_RDONLY)) == -1)
		return (NULL);
	if (fstat(fd, &st) == -1) {
		close(fd);
		return (NULL);
	}
	if (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		return (NULL);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(read, fd, banner, len);
	close(fd);

	if (n != len) {
		free(banner);
		return (NULL);
	}
	banner[n] = '\0';

	return (banner);
}

void
userauth_send_banner(const char *msg)
{
	if (datafellows & SSH_BUG_BANNER)
		return;

	packet_start(SSH2_MSG_USERAUTH_BANNER);
	packet_put_cstring(msg);
	packet_put_cstring("");		/* language, unused */
	packet_send();
	debug("%s: sent", __func__);
}

static void
userauth_banner(void)
{
	char *banner = NULL;

	if (options.banner == NULL || (datafellows & SSH_BUG_BANNER) != 0)
		return;

	if ((banner = PRIVSEP(auth2_read_banner())) == NULL)
		goto done;
	userauth_send_banner(banner);

done:
	free(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
void
do_authentication2(Authctxt *authctxt)
{
	dispatch_init(&dispatch_protocol_error);
	dispatch_set(SSH2_MSG_SERVICE_REQUEST, &input_service_request);
	dispatch_run(DISPATCH_BLOCK, &authctxt->success, authctxt);
}

/*ARGSUSED*/
static int
input_service_request(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	u_int len;
	int acceptit = 0;
	char *service = packet_get_cstring(&len);
	packet_check_eom();

	if (authctxt == NULL)
		fatal("input_service_request: no authctxt");

	if (strcmp(service, "ssh-userauth") == 0) {
		if (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			dispatch_set(SSH2_MSG_USERAUTH_REQUEST, &input_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	if (acceptit) {
		packet_start(SSH2_MSG_SERVICE_ACCEPT);
		packet_put_cstring(service);
		packet_send();
		packet_write_wait();
	} else {
		debug("bad service request %s", service);
		packet_disconnect("bad service request %s", service);
	}
	free(service);
	return 0;
}

/*ARGSUSED*/
static int
input_userauth_request(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Authmethod *m = NULL;
	char *user, *service, *method, *style = NULL;
	int authenticated = 0;

	if (authctxt == NULL)
		fatal("input_userauth_request: no authctxt");

	user = packet_get_cstring(NULL);
	service = packet_get_cstring(NULL);
	method = packet_get_cstring(NULL);
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	if ((style = strchr(user, ':')) != NULL)
		*style++ = 0;

	if (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = PRIVSEP(getpwnamallow(user));
		authctxt->user = xstrdup(user);
		if (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2("input_userauth_request: setting up authctxt for %s", user);
		} else {
			logit("input_userauth_request: invalid user %s", user);
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			PRIVSEP(audit_event(SSH_INVALID_USER));
#endif
		}
#ifdef USE_PAM
		if (options.use_pam)
			PRIVSEP(start_pam(authctxt));
#endif
		setproctitle("%s%s", authctxt->valid ? user : "unknown",
		    use_privsep ? " [net]" : "");
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : NULL;
		if (use_privsep)
			mm_inform_authserv(service, style);
		userauth_banner();
		if (auth2_setup_methods_lists(authctxt) != 0)
			packet_disconnect("no authentication methods enabled");
	} else if (strcmp(user, authctxt->user) != 0 ||
	    strcmp(service, authctxt->service) != 0) {
		packet_disconnect("Change of username or service not allowed: "
		    "(%s,%s) -> (%s,%s)",
		    authctxt->user, authctxt->service, user, service);
	}
	/* reset state */
	auth2_challenge_stop(authctxt);

#ifdef GSSAPI
	/* XXX move to auth2_gssapi_stop() */
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
#endif

	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	if (m != NULL && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(authctxt);
	}
	userauth_finish(authctxt, authenticated, method, NULL);

	free(service);
	free(user);
	free(method);
	return 0;
}

void
userauth_finish(Authctxt *authctxt, int authenticated, const char *method,
    const char *submethod)
{
	char *methods;
	int partial = 0;

	if (!authctxt->valid && authenticated)
		fatal("INTERNAL ERROR: authenticated invalid user %s",
		    authctxt->user);
	if (authenticated && authctxt->postponed)
		fatal("INTERNAL ERROR: authenticated and postponed");

	/* Special handling for root */
	if (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_root_allowed(method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		PRIVSEP(audit_event(SSH_LOGIN_ROOT_DENIED));
#endif
	}

	if (authenticated && options.num_auth_methods != 0) {
		if (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(authctxt, authenticated, partial, method, submethod);

	if (authctxt->postponed)
		return;

#ifdef USE_PAM
	if (options.use_pam && authenticated) {
		if (!PRIVSEP(do_pam_account())) {
			/* if PAM returned a message, send it to the user */
			if (buffer_len(&loginmsg) > 0) {
				buffer_append(&loginmsg, "\0", 1);
				userauth_send_banner(buffer_ptr(&loginmsg));
				packet_write_wait();
			}
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

#ifdef _UNICOS
	if (authenticated && cray_access_denied(authctxt->user)) {
		authenticated = 0;
		fatal("Access denied for user %s.", authctxt->user);
	}
#endif /* _UNICOS */

	if (authenticated == 1) {
		/* turn off userauth */
		dispatch_set(SSH2_MSG_USERAUTH_REQUEST, &dispatch_protocol_ignore);
		packet_start(SSH2_MSG_USERAUTH_SUCCESS);
		packet_send();
		packet_write_wait();
		/* now we can break out */
		authctxt->success = 1;
	} else {

		/* Allow initial try of "none" auth without failure penalty */
		if (!partial && !authctxt->server_caused_failure &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		if (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			PRIVSEP(audit_event(SSH_LOGIN_EXCEED_MAXTRIES));
#endif
			auth_maxtries_exceeded(authctxt);
		}
		methods = authmethods_get(authctxt);
		debug3("%s: failure partial=%d next methods=\"%s\"", __func__,
		    partial, methods);
		packet_start(SSH2_MSG_USERAUTH_FAILURE);
		packet_put_cstring(methods);
		packet_put_char(partial);
		packet_send();
		packet_write_wait();
		free(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
int
auth2_method_allowed(Authctxt *authctxt, const char *method,
    const char *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	if (options.num_auth_methods == 0)
		return 1;
	for (i = 0; i < authctxt->num_auth_methods; i++) {
		if (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			return 1;
	}
	return 0;
}

static char *
authmethods_get(Authctxt *authctxt)
{
	Buffer b;
	char *list;
	u_int i;

	buffer_init(&b);
	for (i = 0; authmethods[i] != NULL; i++) {
		if (strcmp(authmethods[i]->name, "none") == 0)
			continue;
		if (authmethods[i]->enabled == NULL ||
		    *(authmethods[i]->enabled) == 0)
			continue;
		if (!auth2_method_allowed(authctxt, authmethods[i]->name,
		    NULL))
			continue;
		if (buffer_len(&b) > 0)
			buffer_append(&b, ",", 1);
		buffer_append(&b, authmethods[i]->name,
		    strlen(authmethods[i]->name));
	}
	buffer_append(&b, "\0", 1);
	list = xstrdup(buffer_ptr(&b));
	buffer_free(&b);
	return list;
}

static Authmethod *
authmethod_lookup(Authctxt *authctxt, const char *name)
{
	int i;

	if (name != NULL)
		for (i = 0; authmethods[i] != NULL; i++)
			if (authmethods[i]->enabled != NULL &&
			    *(authmethods[i]->enabled) != 0 &&
			    strcmp(name, authmethods[i]->name) == 0 &&
			    auth2_method_allowed(authctxt,
			    authmethods[i]->name, NULL))
				return authmethods[i];
	debug2("Unrecognized authentication method name: %s",
	    name ? name : "NULL");
	return NULL;
}

/*
 * Check a comma-separated list of methods for validity. Is need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
int
auth2_methods_valid(const char *_methods, int need_enable)
{
	char *methods, *omethods, *method, *p;
	u_int i, found;
	int ret = -1;

	if (*_methods == '\0') {
		error("empty authentication method list");
		return -1;
	}
	omethods = methods = xstrdup(_methods);
	while ((method = strsep(&methods, ",")) != NULL) {
		for (found = i = 0; !found && authmethods[i] != NULL; i++) {
			if ((p = strchr(method, ':')) != NULL)
				*p = '\0';
			if (strcmp(method, authmethods[i]->name) != 0)
				continue;
			if (need_enable) {
				if (authmethods[i]->enabled == NULL ||
				    *(authmethods[i]->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					goto out;
				}
			}
			found = 1;
			break;
		}
		if (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			goto out;
		}
	}
	ret = 0;
 out:
	free(omethods);
	return ret;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
int
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	if (options.num_auth_methods == 0)
		return 0;
	debug3("%s: checking methods", __func__);
	authctxt->auth_methods = xcalloc(options.num_auth_methods,
	    sizeof(*authctxt->auth_methods));
	authctxt->num_auth_methods = 0;
	for (i = 0; i < options.num_auth_methods; i++) {
		if (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			continue;
		}
		debug("authentication methods list %d: %s",
		    authctxt->num_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->num_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	if (authctxt->num_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		return -1;
	}
	return 0;
}

static int
list_starts_with(const char *methods, const char *method,
    const char *submethod)
{
	size_t l = strlen(method);
	int match;
	const char *p;

	if (strncmp(methods, method, l) != 0)
		return MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	if (*p == ':') {
		if (!submethod)
			return MATCH_PARTIAL;
		l = strlen(submethod);
		p += 1;
		if (strncmp(submethod, p, l))
			return MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	if (*p != ',' && *p != '\0')
		return MATCH_NONE;
	return match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
static int
remove_method(char **methods, const char *method, const char *submethod)
{
	char *omethods = *methods, *p;
	size_t l = strlen(method);
	int match;

	match = list_starts_with(omethods, method, submethod);
	if (match != MATCH_METHOD && match != MATCH_BOTH)
		return 0;
	p = omethods + l;
	if (submethod && match == MATCH_BOTH)
		p += 1 + strlen(submethod); /* include colon */
	if (*p == ',')
		p++;
	*methods = xstrdup(p);
	free(omethods);
	return 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful. Updates the list of
 * previously successful authentication methods that can be exposed to PAM.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
int
auth2_update_methods_lists(Authctxt *authctxt, const char *method,
    const char *submethod)
{
	u_int i, found = 0;
  char *am_copy = NULL;
  char *method_details = NULL;
  char *fp = NULL;
  Key * good_key = NULL;

	debug3("%s: updating methods list after \"%s\"", __func__, method);
	for (i = 0; i < authctxt->num_auth_methods; i++) {
		if (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			continue;
		found = 1;
		if (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			return 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	if (!found)
		fatal("%s: method not in AuthenticationMethods", __func__);

  if (strcmp(method, "publickey") == 0 ||
      strcmp(method, "hostbased") == 0) {
    good_key = authctxt->prev_userkeys[authctxt->nprev_userkeys - 1];
    if (key_is_cert(good_key)) {
		  fp = sshkey_fingerprint(good_key->cert->signature_key,
          options.fingerprint_hash, SSH_FP_DEFAULT);

      xasprintf(&method_details, "%s ID %s (serial %llu) CA %s %s",
		    key_type(good_key), good_key->cert->key_id,
		    (unsigned long long) good_key->cert->serial,
		    key_type(good_key->cert->signature_key),
		    fp == NULL ? "(null)" : fp);
	  } else {
		  fp = sshkey_fingerprint(good_key, options.fingerprint_hash,
		        SSH_FP_DEFAULT);
		  xasprintf(&method_details, "%s %s", key_type(good_key),
		    fp == NULL ? "(null)" : fp);
	  }
    free(fp);
  }

  if (authctxt->last_auth_methods == NULL) {
    if (method_details) {
      xasprintf(&authctxt->last_auth_methods, "%s %s", method, method_details);
    } else {
      authctxt->last_auth_methods = xstrdup(method);
    }
  } else {
    am_copy = authctxt->last_auth_methods;
    if (method_details) {
      xasprintf(&authctxt->last_auth_methods, "%s,%s %s", am_copy, method, method_details);
    } else {
      xasprintf(&authctxt->last_auth_methods, "%s,%s", am_copy, method);
    }
    free(am_copy);
  }

  free(method_details);

  return 0;
}


