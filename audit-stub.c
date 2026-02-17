/*
 * Copyright (c) 2004, 2005 Ajay Kini.  All rights reserved.
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

/*
 * Stub audit functions for SSH client builds.
 * The real implementations are in audit.c for server builds.
 *
 * These stubs are used when SSH_AUDIT_EVENTS is not defined,
 * or when building client binaries that link with libssh.a
 * but should not perform actual auditing.
 */

#include "includes.h"

#include "audit.h"
#include "log.h"

#ifndef CUSTOM_SSH_AUDIT_EVENTS

/*
 * Stub audit_event function for client builds.
 * Does nothing - audit events are only meaningful on the server side.
 */
void
audit_event(struct ssh *ssh, ssh_audit_event_t event)
{
	/* No-op for client */
}

/*
 * Stub audit_connection_from function for client builds.
 */
void
audit_connection_from(const char *host, int port)
{
	/* No-op for client */
}

/*
 * Stub audit_session_open function for client builds.
 */
void
audit_session_open(struct logininfo *li)
{
	/* No-op for client */
}

/*
 * Stub audit_session_close function for client builds.
 */
void
audit_session_close(struct logininfo *li)
{
	/* No-op for client */
}

/*
 * Stub audit_run_command function for client builds.
 */
void
audit_run_command(const char *command)
{
	/* No-op for client */
}

/*
 * Stub audit_classify_auth function for client builds.
 */
ssh_audit_event_t
audit_classify_auth(const char *method)
{
	/* Return unknown for client */
	return SSH_AUDIT_UNKNOWN;
}

#endif /* !CUSTOM_SSH_AUDIT_EVENTS */