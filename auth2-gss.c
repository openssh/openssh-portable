/* $OpenBSD: auth2-gss.c,v 1.22 2015/01/19 20:07:45 markus Exp $ */

/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AS IS'' AND ANY EXPRESS OR
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

#ifdef GSSAPI

#include <sys/types.h>

#include <stdarg.h>

#include "xmalloc.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "ssh2.h"
#include "log.h"
#include "dispatch.h"
#include "buffer.h"
#include "misc.h"
#include "servconf.h"
#include "packet.h"
#include "ssh-gss.h"
#include "monitor_wrap.h"

extern ServerOptions options;

static int input_gssapi_token(int type, u_int32_t plen, void *ctxt);
static int input_gssapi_mic(int type, u_int32_t plen, void *ctxt);
static int input_gssapi_exchange_complete(int type, u_int32_t plen, void *ctxt);
static int input_gssapi_errtok(int, u_int32_t, void *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
static int
userauth_gssapi(Authctxt *authctxt)
{
	gss_OID_desc goid = {0, NULL};
	Gssctxt *ctxt = NULL;
	int mechs;
	int present;
	OM_uint32 ms;
	u_int len;
	u_char *doid = NULL;

	if (!authctxt->valid || authctxt->user == NULL)
		return (0);

	mechs = packet_get_int();
	if (mechs == 0) {
		debug("Mechanism negotiation is not supported");
		return (0);
	}

	do {
		mechs--;

		free(doid);

		present = 0;
		doid = packet_get_string(&len);

		if (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.length   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} else {
			logit("Badly formed OID received");
		}
	} while (mechs > 0 && !present);

	if (!present) {
		free(doid);
		authctxt->server_caused_failure = 1;
		return (0);
	}

	if (GSS_ERROR(PRIVSEP(ssh_gssapi_server_ctx(&ctxt, &goid)))) {
		if (ctxt != NULL)
			ssh_gssapi_delete_ctx(&ctxt);
		free(doid);
		authctxt->server_caused_failure = 1;
		return (0);
	}

	authctxt->methoddata = (void *)ctxt;

	packet_start(SSH2_MSG_USERAUTH_GSSAPI_RESPONSE);

	/* Return the OID that we received */
	packet_put_string(doid, len);

	packet_send();
	free(doid);

	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, &input_gssapi_token);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, &input_gssapi_errtok);
	authctxt->postponed = 1;

	return (0);
}

static int
input_gssapi_token(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 maj_status, min_status, flags;
	u_int len;

	if (authctxt == NULL || (authctxt->methoddata == NULL && !use_privsep))
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	recv_tok.value = packet_get_string(&len);
	recv_tok.length = len; /* u_int vs. size_t */

	packet_check_eom();

	maj_status = PRIVSEP(ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags));

	free(recv_tok.value);

	if (GSS_ERROR(maj_status)) {
		if (send_tok.length != 0) {
			packet_start(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK);
			packet_put_string(send_tok.value, send_tok.length);
			packet_send();
		}
		authctxt->postponed = 0;
		dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
		userauth_finish(authctxt, 0, "gssapi-with-mic", NULL);
	} else {
		if (send_tok.length != 0) {
			packet_start(SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
			packet_put_string(send_tok.value, send_tok.length);
			packet_send();
		}
		if (maj_status == GSS_S_COMPLETE) {
			dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
			if (flags & GSS_C_INTEG_FLAG)
				dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_MIC,
				    &input_gssapi_mic);
			else
				dispatch_set(
				    SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &input_gssapi_exchange_complete);
		}
	}

	gss_release_buffer(&min_status, &send_tok);
	return 0;
}

static int
input_gssapi_errtok(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 maj_status;
	u_int len;

	if (authctxt == NULL || (authctxt->methoddata == NULL && !use_privsep))
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	recv_tok.value = packet_get_string(&len);
	recv_tok.length = len;

	packet_check_eom();

	/* Push the error token into GSSAPI to see what it says */
	maj_status = PRIVSEP(ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, NULL));

	free(recv_tok.value);

	/* We can't return anything to the client, even if we wanted to */
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);

	/* The client will have already moved on to the next auth */

	gss_release_buffer(&maj_status, &send_tok);
	return 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

static int
input_gssapi_exchange_complete(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	int authenticated;

	if (authctxt == NULL || (authctxt->methoddata == NULL && !use_privsep))
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	packet_check_eom();

	authenticated = PRIVSEP(ssh_gssapi_userok(authctxt->user));

	if (authenticated)
		authctxt->last_details = ssh_gssapi_get_displayname();

	authctxt->postponed = 0;
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_MIC, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
	userauth_finish(authctxt, authenticated, "gssapi-with-mic", NULL);
	return 0;
}

static int
input_gssapi_mic(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
	int authenticated = 0;
	Buffer b;
	gss_buffer_desc mic, gssbuf;
	u_int len;

	if (authctxt == NULL || (authctxt->methoddata == NULL && !use_privsep))
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	mic.value = packet_get_string(&len);
	mic.length = len;

	ssh_gssapi_buildmic(&b, authctxt->user, authctxt->service,
	    "gssapi-with-mic");

	gssbuf.value = buffer_ptr(&b);
	gssbuf.length = buffer_len(&b);

	if (!GSS_ERROR(PRIVSEP(ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic))))
		authenticated = PRIVSEP(ssh_gssapi_userok(authctxt->user));
	else
		logit("GSSAPI MIC check failed");

	if (authenticated)
		authctxt->last_details = ssh_gssapi_get_displayname();

	buffer_free(&b);
	free(mic.value);

	authctxt->postponed = 0;
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_MIC, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
	userauth_finish(authctxt, authenticated, "gssapi-with-mic", NULL);
	return 0;
}

Authmethod method_gssapi = {
	"gssapi-with-mic",
	userauth_gssapi,
	&options.gss_authentication
};

#endif /* GSSAPI */
