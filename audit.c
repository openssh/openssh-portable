/*
 * Copyright (c) 2004, 2005 Darren Tucker.  All rights reserved.
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

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#ifdef _AIX
# include <sys/audit.h>
# include <usersec.h>
#endif

#ifdef SSH_AUDIT_EVENTS

#include "audit.h"
#include "log.h"
#include "hostfile.h"
#include "auth.h"

/*
 * Care must be taken when using this since it WILL NOT be initialized when
 * audit_connection_from() is called and MAY NOT be initialized when
 * audit_event(CONNECTION_ABANDON) is called.  Test for NULL before using.
 */
extern Authctxt *the_authctxt;

/* Maybe add the audit class to struct Authmethod? */
ssh_audit_event_t
audit_classify_auth(const char *method)
{
	if (strcmp(method, "none") == 0)
		return SSH_AUTH_FAIL_NONE;
	else if (strcmp(method, "password") == 0)
		return SSH_AUTH_FAIL_PASSWD;
	else if (strcmp(method, "publickey") == 0 ||
	    strcmp(method, "rsa") == 0)
		return SSH_AUTH_FAIL_PUBKEY;
	else if (strncmp(method, "keyboard-interactive", 20) == 0 ||
	    strcmp(method, "challenge-response") == 0)
		return SSH_AUTH_FAIL_KBDINT;
	else if (strcmp(method, "hostbased") == 0 ||
	    strcmp(method, "rhosts-rsa") == 0)
		return SSH_AUTH_FAIL_HOSTBASED;
	else if (strcmp(method, "gssapi-with-mic") == 0)
		return SSH_AUTH_FAIL_GSSAPI;
	else
		return SSH_AUDIT_UNKNOWN;
}

/* helper to return supplied username */
const char *
audit_username(void)
{
	static const char unknownuser[] = "(unknown user)";
	static const char invaliduser[] = "(invalid user)";

	if (the_authctxt == NULL || the_authctxt->user == NULL)
		return (unknownuser);
	if(the_authctxt->user != NULL)
			return (the_authctxt->user);
	if (!the_authctxt->valid)
			return (invaliduser);	
	
	return (the_authctxt->user);
}

const char *
audit_event_lookup(ssh_audit_event_t ev)
{
	int i;
	static struct event_lookup_struct {
		ssh_audit_event_t event;
		const char *name;
	} event_lookup[] = {
#ifdef _AIX
		/*
		 * These envent names comply with AIX audit requirements.
		 */
		{SSH_LOGIN_EXCEED_MAXTRIES,	"SSH_exceedmtrix"},
		{SSH_LOGIN_ROOT_DENIED,		"SSH_rootdned"},
		{SSH_AUTH_SUCCESS,		"SSH_authsuccess"},
		{SSH_AUTH_FAIL_NONE,		"SSH_failnone"},
		{SSH_AUTH_FAIL_PASSWD,		"SSH_failpasswd"},
		{SSH_AUTH_FAIL_KBDINT,		"SSH_failkbdint"},
		{SSH_AUTH_FAIL_PUBKEY,		"SSH_failpubkey"},
		{SSH_AUTH_FAIL_HOSTBASED,	"SSH_failhstbsd"},
		{SSH_AUTH_FAIL_GSSAPI,		"SSH_failgssapi"},
		{SSH_INVALID_USER,		"SSH_invldusr"},
		{SSH_NOLOGIN,			"SSH_nologin"},
		{SSH_CONNECTION_CLOSE,		"SSH_connclose"},
		{SSH_CONNECTION_ABANDON,	"SSH_connabndn"},
		{SSH_BAD_PCKT,					"SSH_badpckt"},
		{SSH_CIPHER_NO_MATCH,			"SSH_cipmismatch"},
		{SSH_SESSION_OPEN,				"SSH_sessionopn"},
		{SSH_AUDIT_UNKNOWN,		"SSH_auditknwn"}
#else
		/* Standard descriptive event names for non-AIX systems */
		{SSH_LOGIN_EXCEED_MAXTRIES,	"LOGIN_EXCEED_MAXTRIES"},
		{SSH_LOGIN_ROOT_DENIED,		"LOGIN_ROOT_DENIED"},
		{SSH_AUTH_SUCCESS,		"AUTH_SUCCESS"},
		{SSH_AUTH_FAIL_NONE,		"AUTH_FAIL_NONE"},
		{SSH_AUTH_FAIL_PASSWD,		"AUTH_FAIL_PASSWD"},
		{SSH_AUTH_FAIL_KBDINT,		"AUTH_FAIL_KBDINT"},
		{SSH_AUTH_FAIL_PUBKEY,		"AUTH_FAIL_PUBKEY"},
		{SSH_AUTH_FAIL_HOSTBASED,	"AUTH_FAIL_HOSTBASED"},
		{SSH_AUTH_FAIL_GSSAPI,		"AUTH_FAIL_GSSAPI"},
		{SSH_INVALID_USER,		"INVALID_USER"},
		{SSH_NOLOGIN,			"NOLOGIN"},
		{SSH_CONNECTION_CLOSE,		"CONNECTION_CLOSE"},
		{SSH_CONNECTION_ABANDON,	"CONNECTION_ABANDON"},
		{SSH_AUDIT_UNKNOWN,		"AUDIT_UNKNOWN"}
#endif /* _AIX */
	};

	for (i = 0; event_lookup[i].event != SSH_AUDIT_UNKNOWN; i++)
		if (event_lookup[i].event == ev)
			break;
	return (event_lookup[i].name);
}

# ifndef CUSTOM_SSH_AUDIT_EVENTS
/*
 * Null implementations of audit functions.
 * These get used if SSH_AUDIT_EVENTS is defined but no audit module is enabled.
 */

/*
 * Called after a connection has been accepted but before any authentication
 * has been attempted.
 */
void
audit_connection_from(const char *host, int port)
{
	debug("audit connection from %s port %d euid %d", host, port,
	    (int)geteuid());
}

/*
 * Called when various events occur (see audit.h for a list of possible
 * events and what they mean).
 */
void
audit_event(struct ssh *ssh, ssh_audit_event_t event)
{
#ifdef _AIX
	char buf[1024];
	const char *username;
	const char *event_name;
	const char *remote_ip;
	int ret;
	uid_t auth_uid;  /* UID of the user attempting authentication */
	int res = 0;  /* AIX audit result code: 0 = success */

	/* Debug: Log that audit_event was called */
	debug("audit_event: called with event=%d", event);
	
	/* Get username from authctxt */
	username = audit_username();
	
	/* Get the UID of the authenticating user */
	auth_uid = (uid_t)-1;  /* Default to -1 if user doesn't exist */
	
	/* On AIX, use getuserattr to get UID from username */
	if (the_authctxt != NULL && the_authctxt->user != NULL) {
		int uid_val;
		if (getuserattr(the_authctxt->user, S_ID, &uid_val, SEC_INT) == 0) {
			auth_uid = (uid_t)uid_val;
		}
	}

	/* On other systems, use getpwnam or authctxt->pw */
	if (the_authctxt != NULL && the_authctxt->pw != NULL) {
		auth_uid = the_authctxt->pw->pw_uid;
	} else if (the_authctxt != NULL && the_authctxt->user != NULL) {
		struct passwd *pw = getpwnam(the_authctxt->user);
		if (pw != NULL) {
			auth_uid = pw->pw_uid;
		}
	}
	
	event_name = audit_event_lookup(event);
	
	/* Set audit result code based on event type */
	switch (event) {
	case SSH_AUTH_FAIL_NONE:
	case SSH_AUTH_FAIL_PASSWD:
	case SSH_AUTH_FAIL_KBDINT:
	case SSH_AUTH_FAIL_PUBKEY:
	case SSH_AUTH_FAIL_HOSTBASED:
	case SSH_AUTH_FAIL_GSSAPI:
	case SSH_INVALID_USER:
	case SSH_BAD_PCKT:
	case SSH_CIPHER_NO_MATCH:
		res = 1;  /* Failure */
		break;
	default:
		res = 0;  /* Success */
		break;
	}
	
	/* Handle NULL ssh pointer gracefully */
	if (ssh != NULL) {
		remote_ip = ssh_remote_ipaddr(ssh);
	} else {
		remote_ip = "(unknown)";
	}

	/* Build audit message with proper error checking */
	if (auth_uid == (uid_t)-1) {
		ret = snprintf(buf, sizeof(buf),
		    "audit event for user %s event %d (%s) remote ip (%s)",
		     username, event, event_name, remote_ip);
	} else {
		ret = snprintf(buf, sizeof(buf),
		    "audit event auth_uid %u user %s event %d (%s) remote ip (%s)",
		    (unsigned int)auth_uid, username, event, event_name, remote_ip);
	}

	/* Check for truncation */
	if (ret < 0 || (size_t)ret >= sizeof(buf)) {
		debug("audit_event: message truncated (needed %d bytes)", ret);
	}

	/* Log to debug output */
	if (auth_uid == (uid_t)-1) {
		debug("audit event auth_uid -1 user %s event %d (%s) remote ip (%s)", 
			username, event, event_name, remote_ip);
	} else {
		debug("audit event auth_uid %u user %s event %d (%s) remote ip (%s)",
		    (unsigned int)auth_uid, username, event, event_name, remote_ip);
	}

	/* Write to AIX audit subsystem with required format */
	if (auditwrite(event_name, res, buf, strlen(buf) + 1, 0) < 0) {
		error("auditwrite failed for event %s: %s",
		    event_name, strerror(errno));
	}
#else
	debug("audit event euid %d user %s event %d (%s)", geteuid(),
	    audit_username(), event, audit_event_lookup(event));
#endif

}

/*
 * Called when a user session is started.  Argument is the tty allocated to
 * the session, or NULL if no tty was allocated.
 *
 * Note that this may be called multiple times if multiple sessions are used
 * within a single connection.
 */
void
audit_session_open(struct logininfo *li)
{
	const char *t = li->line ? li->line : "(no tty)";
#ifdef _AIX
	const char *username;
	const char *hostname;
	const char *event_name;
	char buf[1024];
	int ret;
	uid_t auth_uid;

	int res = 0;  /* AIX audit result code: 0 = success for session open */
	
	/* Use username from logininfo if available, otherwise from authctxt */
	if (li->username[0] != '\0') {
		username = li->username;
	} else {
		username = audit_username();
	}
	
	/* Use hostname from logininfo if available */
	if (li->hostname[0] != '\0') {
		hostname = li->hostname;
	} else {
		hostname = "(unknown)";
	}
	
	/* Get the UID from logininfo */
	auth_uid = li->uid;
	
	event_name = audit_event_lookup(SSH_SESSION_OPEN);

	/* Build audit message with logininfo details */
	if (auth_uid == (uid_t)-1) {
		ret = snprintf(buf, sizeof(buf),
		    "audit session open auth_uid -1 user %s tty %s hostname %s pid %ld",
			 username, t, hostname, (long)li->pid);
	} else {
		ret = snprintf(buf, sizeof(buf),
		    "audit session open auth_uid %u user %s tty %s hostname %s pid %ld",
		    (unsigned int)auth_uid, username, t, hostname, (long)li->pid);
	}

	/* Check for truncation */
	if (ret < 0 || (size_t)ret >= sizeof(buf)) {
		debug("audit_session_open: message truncated (needed %d bytes)", ret);
	}

	/* Log to debug output */
	if (auth_uid == (uid_t)-1) {
		debug("audit session open auth_uid -1 user %s tty %s hostname %s pid %ld",
			 username, t, hostname, (long)li->pid);
	} else {
		debug("audit session open auth_uid %u user %s tty %s hostname %s pid %ld",
		    (unsigned int)auth_uid, username, t, hostname, (long)li->pid);
	}

	/* Write to AIX audit subsystem */
	if (auditwrite(event_name, res, buf, strlen(buf) + 1, 0) < 0) {
		error("auditwrite failed for event %s: %s",
		    event_name, strerror(errno));
	}
#else
	debug("audit session open euid %d user %s tty name %s", geteuid(),
	    audit_username(), t);
#endif
}

/*
 * Called when a user session is closed.  Argument is the tty allocated to
 * the session, or NULL if no tty was allocated.
 *
 * Note that this may be called multiple times if multiple sessions are used
 * within a single connection.
 */
void
audit_session_close(struct logininfo *li)
{
	const char *t = li->line ? li->line : "(no tty)";

	debug("audit session close euid %d user %s tty name %s", geteuid(),
	    audit_username(), t);
}

/*
 * This will be called when a user runs a non-interactive command.  Note that
 * it may be called multiple times for a single connection since SSH2 allows
 * multiple sessions within a single connection.
 */
void
audit_run_command(const char *command)
{
	debug("audit run command euid %d user %s command '%.200s'", geteuid(),
	    audit_username(), command);
}
# endif  /* !defined CUSTOM_SSH_AUDIT_EVENTS */
#endif /* SSH_AUDIT_EVENTS */
