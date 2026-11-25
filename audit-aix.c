/*
 * Copyright (c) 2026 OpenSSH contributors.  All rights reserved.
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
#if defined(USE_AIX_AUDIT)

#include <sys/types.h>
#include <sys/audit.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "audit.h"
#include "hostfile.h"
#include "auth.h"
#include "canohost.h"
#include "packet.h"
#include "loginrec.h"

extern Authctxt *the_authctxt;
const char *audit_username(void);

/*
 * auditwrite() is exported by libc.a but is not declared in <sys/audit.h>
 * (checked on AIX 7.3 TL4, which declares only auditlog()).  Declare it here
 * to match the documented interface: (Event, Result, Buffer1, Length1, ...)
 * with a NULL-terminated list of (buffer, length) pairs.
 */
extern int auditwrite(char *, int, ...);

#define AIX_AUDIT_MSGLEN	512

/*
 * Static table mapping ssh_audit_event_t enum values to AIX audit event names.
 * All event names must be registered in /etc/security/audit/events and be 15
 * characters or shorter (AIX limit is 15 chars + null).
 */
struct aix_event_entry {
	ssh_audit_event_t event;
	const char *name;
};

static const struct aix_event_entry aix_events[] = {
	{ SSH_LOGIN_EXCEED_MAXTRIES,	"SSH_exceedmtrix" },
	{ SSH_LOGIN_ROOT_DENIED,	"SSH_rootdned" },
	{ SSH_AUTH_SUCCESS,		"SSH_authsuccess" },
	{ SSH_AUTH_FAIL_NONE,		"SSH_failnone" },
	{ SSH_AUTH_FAIL_PASSWD,		"SSH_failpasswd" },
	{ SSH_AUTH_FAIL_KBDINT,		"SSH_failkbdint" },
	{ SSH_AUTH_FAIL_PUBKEY,		"SSH_failpubkey" },
	{ SSH_AUTH_FAIL_HOSTBASED,	"SSH_failhstbsd" },
	{ SSH_AUTH_FAIL_GSSAPI,		"SSH_failgssapi" },
	{ SSH_INVALID_USER,		"SSH_invldusr" },
	{ SSH_NOLOGIN,			"SSH_nologin" },
	{ SSH_CONNECTION_CLOSE,		"SSH_connclose" },
	{ SSH_CONNECTION_ABANDON,	"SSH_connabndn" },
	{ SSH_BAD_PCKT,			"SSH_badpckt" },
	{ SSH_CIPHER_NO_MATCH,		"SSH_cipmismatch" },
	{ SSH_SESSION_OPEN,		"SSH_sessionopn" },
	{ SSH_AUDIT_UNKNOWN,		"SSH_auditknwn" }
};

/*
 * Cached connection information from audit_connection_from().
 * Used when the_authctxt / ssh are not yet available or when ssh is NULL.
 */
static char cached_remote_ip[64] = "UNKNOWN";
static int cached_remote_port = 0;

/*
 * Map an audit event enum to its AIX audit event name string.
 */
static const char *
aix_audit_event_name(ssh_audit_event_t event)
{
	u_int i;

	for (i = 0; i < sizeof(aix_events) / sizeof(aix_events[0]); i++) {
		if (aix_events[i].event == event)
			return (aix_events[i].name);
	}
	return ("SSH_auditknwn");
}

/*
 * Classify event outcome as AUDIT_OK or AUDIT_FAIL.
 * SSH_AUTH_SUCCESS, SSH_SESSION_OPEN and SSH_CONNECTION_CLOSE are AUDIT_OK;
 * all other events represent failures or errors.
 */
static int
aix_audit_event_result(ssh_audit_event_t event)
{
	switch (event) {
	case SSH_AUTH_SUCCESS:
	case SSH_SESSION_OPEN:
	case SSH_CONNECTION_CLOSE:
		return AUDIT_OK;
	default:
		return AUDIT_FAIL;
	}
}

/*
 * Obtain username for the audit event.
 */
static const char *
aix_audit_user(ssh_audit_event_t event)
{
	switch (event) {
	case SSH_CONNECTION_CLOSE:
	case SSH_CONNECTION_ABANDON:
	case SSH_BAD_PCKT:
	case SSH_CIPHER_NO_MATCH:
		if (the_authctxt != NULL && the_authctxt->user != NULL)
			return (the_authctxt->user);
		return (NULL);
	case SSH_INVALID_USER:
	case SSH_LOGIN_ROOT_DENIED:
	case SSH_LOGIN_EXCEED_MAXTRIES:
	case SSH_NOLOGIN:
		if (the_authctxt != NULL && the_authctxt->user != NULL)
			return (the_authctxt->user);
		return (audit_username());
	default:
		return (audit_username());
	}
}

/*
 * Determine the remote IP address and port, falling back to cached values.
 */
static void
aix_audit_get_connection_info(struct ssh *ssh, const char **ip, int *port)
{
	const char *remote_ip = NULL;
	int remote_port = 0;

	if (ssh != NULL) {
		remote_ip = ssh_remote_ipaddr(ssh);
		remote_port = ssh_remote_port(ssh);
	}

	if (remote_ip == NULL || strcmp(remote_ip, "UNKNOWN") == 0 ||
	    remote_ip[0] == '\0')
		*ip = cached_remote_ip;
	else
		*ip = remote_ip;

	if (remote_port <= 0)
		*port = cached_remote_port;
	else
		*port = remote_port;
}

/*
 * Build audit tail message for the specified event into a bounded buffer.
 * Optional 'detail' string allows callers (e.g. Sub-Task 5 packet/cipher errors)
 * to provide extra contextual error information.
 */
static void
aix_audit_build_message(ssh_audit_event_t event, const char *user,
    const char *ip, int port, const char *detail, char *buf, size_t buflen)
{
	const char *u = (user != NULL && user[0] != '\0') ? user : "(unknown user)";
	const char *h = (ip != NULL && ip[0] != '\0') ? ip : "UNKNOWN";

	switch (event) {
	case SSH_AUTH_SUCCESS:
		if (detail != NULL && detail[0] != '\0')
			snprintf(buf, buflen,
			    "user=%s ip=%s port=%d method=%s result=success",
			    u, h, port, detail);
		else
			snprintf(buf, buflen,
			    "user=%s ip=%s port=%d result=success",
			    u, h, port);
		break;
	case SSH_AUTH_FAIL_NONE:
		snprintf(buf, buflen,
		    "user=%s ip=%s port=%d method=none result=failed",
		    u, h, port);
		break;
	case SSH_AUTH_FAIL_PASSWD:
		snprintf(buf, buflen,
		    "user=%s ip=%s port=%d method=password result=failed",
		    u, h, port);
		break;
	case SSH_AUTH_FAIL_KBDINT:
		snprintf(buf, buflen,
		    "user=%s ip=%s port=%d method=keyboard-interactive result=failed",
		    u, h, port);
		break;
	case SSH_AUTH_FAIL_PUBKEY:
		snprintf(buf, buflen,
		    "user=%s ip=%s port=%d method=publickey result=failed",
		    u, h, port);
		break;
	case SSH_AUTH_FAIL_HOSTBASED:
		snprintf(buf, buflen,
		    "user=%s ip=%s port=%d method=hostbased result=failed",
		    u, h, port);
		break;
	case SSH_AUTH_FAIL_GSSAPI:
		snprintf(buf, buflen,
		    "user=%s ip=%s port=%d method=gssapi result=failed",
		    u, h, port);
		break;
	case SSH_INVALID_USER:
		if (detail != NULL && detail[0] != '\0')
			snprintf(buf, buflen,
			    "user=%s ip=%s port=%d reason=invalid user (%s)",
			    u, h, port, detail);
		else
			snprintf(buf, buflen,
			    "user=%s ip=%s port=%d reason=invalid user",
			    u, h, port);
		break;
	case SSH_LOGIN_ROOT_DENIED:
		snprintf(buf, buflen,
		    "user=%s ip=%s port=%d reason=root login denied",
		    u, h, port);
		break;
	case SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(buf, buflen,
		    "user=%s ip=%s port=%d reason=maximum authentication attempts exceeded",
		    u, h, port);
		break;
	case SSH_NOLOGIN:
		snprintf(buf, buflen,
		    "user=%s ip=%s port=%d reason=login disabled via nologin",
		    u, h, port);
		break;
	case SSH_CONNECTION_CLOSE:
		if (user != NULL && user[0] != '\0')
			snprintf(buf, buflen,
			    "user=%s ip=%s port=%d result=closed",
			    u, h, port);
		else
			snprintf(buf, buflen,
			    "ip=%s port=%d result=closed",
			    h, port);
		break;
	case SSH_CONNECTION_ABANDON:
		if (user != NULL && user[0] != '\0')
			snprintf(buf, buflen,
			    "user=%s ip=%s port=%d reason=connection abandoned",
			    u, h, port);
		else
			snprintf(buf, buflen,
			    "ip=%s port=%d reason=connection abandoned",
			    h, port);
		break;
	case SSH_BAD_PCKT:
		if (detail != NULL && detail[0] != '\0')
			snprintf(buf, buflen,
			    "ip=%s port=%d reason=bad packet error=%s",
			    h, port, detail);
		else
			snprintf(buf, buflen,
			    "ip=%s port=%d reason=bad packet",
			    h, port);
		break;
	case SSH_CIPHER_NO_MATCH:
		if (detail != NULL && detail[0] != '\0')
			snprintf(buf, buflen,
			    "ip=%s port=%d reason=cipher mismatch error=%s",
			    h, port, detail);
		else
			snprintf(buf, buflen,
			    "ip=%s port=%d reason=cipher mismatch",
			    h, port);
		break;
	case SSH_SESSION_OPEN:
		if (detail != NULL && detail[0] != '\0')
			snprintf(buf, buflen,
			    "user=%s ip=%s port=%d session=%s",
			    u, h, port, detail);
		else
			snprintf(buf, buflen,
			    "user=%s ip=%s port=%d session open",
			    u, h, port);
		break;
	case SSH_AUDIT_UNKNOWN:
	default:
		if (detail != NULL && detail[0] != '\0')
			snprintf(buf, buflen,
			    "event=%d ip=%s port=%d detail=%s",
			    (int)event, h, port, detail);
		else
			snprintf(buf, buflen,
			    "event=%d ip=%s port=%d",
			    (int)event, h, port);
		break;
	}
}

/*
 * Wrapper around AIX auditwrite(3) subroutine.
 *
 * int auditwrite(char *Event, int Result, char *Buffer1, int Length1, ..., NULL);
 * (libc.a; declared locally above because <sys/audit.h> does not declare it.)
 *
 * Returns 0 on success, -1 on error (errno set), per the AIX 7.2 documentation.
 * Errors are logged at debug level and must NEVER fatal() so sshd remains
 * fully operational when AIX auditing is disabled or not configured.
 */
static void
aix_audit_write(const char *event_name, int result, const char *msg)
{
	int rc;
	size_t len;

	if (event_name == NULL || msg == NULL)
		return;

	/*
	 * If auditwrite requires root privilege and we are running as an
	 * unprivileged child, skip to avoid generating unnecessary errors.
	 */
	if (geteuid() != 0) {
		debug3_f("skipping auditwrite for %s: unprivileged process",
		    event_name);
		return;
	}

	len = strlen(msg) + 1;
	/*
	 * Note: auditwrite expects non-const char * pointers and a NULL sentinel.
	 */
	rc = auditwrite((char *)event_name, result, (char *)msg, (int)len,
	    (char *)NULL);
	if (rc != 0) {
		debug_f("auditwrite failed for event %s (result %d): %s",
		    event_name, result, strerror(errno));
	} else {
		debug3_f("auditwrite logged event %s (result %d): %s",
		    event_name, result, msg);
	}
}

/*
 * Set once SSH_CONNECTION_CLOSE has been written for this connection, so a
 * clean close followed by cleanup_exit() does not produce a second record.
 */
static int connection_close_logged;

/*
 * Helper to dispatch an audit event with an optional detail string.
 * Exposed internally so packet-layer hooks (Sub-Task 5) can pass details.
 */
static void
aix_audit_do_event(struct ssh *ssh, ssh_audit_event_t event, const char *detail)
{
	const char *event_name;
	const char *ip;
	int port;
	int result;
	char msg[AIX_AUDIT_MSGLEN];

	/*
	 * cleanup_exit() in the monitor always raises SSH_CONNECTION_ABANDON.
	 * If the user had already logged in, the connection did not fail to
	 * authenticate: report an ordinary close instead, once.
	 */
	if (event == SSH_CONNECTION_ABANDON && the_authctxt != NULL &&
	    the_authctxt->authenticated) {
		if (connection_close_logged)
			return;
		event = SSH_CONNECTION_CLOSE;
	}
	if (event == SSH_CONNECTION_CLOSE)
		connection_close_logged = 1;

	event_name = aix_audit_event_name(event);
	result = aix_audit_event_result(event);
	aix_audit_get_connection_info(ssh, &ip, &port);

	aix_audit_build_message(event, aix_audit_user(event), ip, port, detail,
	    msg, sizeof(msg));

	aix_audit_write(event_name, result, msg);
}

/*
 * OpenSSH Audit API Hooks
 */

void
audit_connection_from(const char *host, int port)
{
	if (host != NULL)
		strlcpy(cached_remote_ip, host, sizeof(cached_remote_ip));
	cached_remote_port = port;
	debug3_f("cached connection from %s port %d",
	    cached_remote_ip, cached_remote_port);
}

void
audit_run_command(const char *cmd)
{
	/* not implemented */
	(void)cmd;
}

void
audit_session_open(struct logininfo *li)
{
	char msg[AIX_AUDIT_MSGLEN];
	const char *user = (li != NULL && li->username[0] != '\0') ?
	    li->username : "(unknown user)";
	const char *line = (li != NULL && li->line[0] != '\0') ?
	    li->line : "(none)";
	const char *host = (li != NULL && li->hostname[0] != '\0') ?
	    li->hostname : "(unknown host)";

	snprintf(msg, sizeof(msg), "user=%s tty=%s host=%s", user, line, host);
	aix_audit_write("SSH_sessionopn", AUDIT_OK, msg);
}

void
audit_session_close(struct logininfo *li)
{
	/* not implemented */
	(void)li;
}

void
audit_event(struct ssh *ssh, ssh_audit_event_t event)
{
	aix_audit_do_event(ssh, event, NULL);
}

void
audit_event_detail(struct ssh *ssh, ssh_audit_event_t event,
    const char *detail)
{
	aix_audit_do_event(ssh, event, detail);
}

#endif /* USE_AIX_AUDIT */
