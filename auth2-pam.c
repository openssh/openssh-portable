#include "includes.h"
RCSID("$Id: auth2-pam.c,v 1.3 2001/01/19 04:26:52 mouring Exp $");

#ifdef USE_PAM
#include "ssh.h"
#include "ssh2.h"
#include "auth.h"
#include "packet.h"
#include "xmalloc.h"
#include "dispatch.h"
#include <security/pam_appl.h>

struct {
	int finished, num_received, num_expected;
	int *prompts;
	struct pam_response *responses;
} context_pam2 = {0, 0, 0, NULL};

static int do_conversation2(int num_msg, const struct pam_message **msg,
			    struct pam_response **resp, void *appdata_ptr);

static struct pam_conv
conv2 = {
	do_conversation2,
	NULL,
};

void input_userauth_info_response_pam(int type, int plen, void *ctxt);

int
auth2_pam(Authctxt *authctxt)
{
	int retval = -1;
	char *method = "PAM";

	if (authctxt->user == NULL)
		fatal("auth2_pam: internal error: no user");

	if (authctxt->valid) {
		conv2.appdata_ptr = authctxt;
		pam_set_conv(&conv2);
	}

	dispatch_set(SSH2_MSG_USERAUTH_INFO_RESPONSE,
		     &input_userauth_info_response_pam);
	retval = (do_pam_authenticate(0) == PAM_SUCCESS);
	dispatch_set(SSH2_MSG_USERAUTH_INFO_RESPONSE, NULL);

#if 0		/* ISSUE: No longer valid, but should this still be
			handled?? */
	userauth_log(authctxt, retval, method);
#endif
	return retval;
}

static int
do_conversation2(int num_msg, const struct pam_message **msg,
		 struct pam_response **resp, void *appdata_ptr)
{
	int echo = 0, i = 0, j = 0, done = 0;
	char *tmp = NULL, *text = NULL;

	context_pam2.finished = 0;
	context_pam2.num_received = 0;
	context_pam2.num_expected = 0;
	context_pam2.prompts = xmalloc(sizeof(int) * num_msg);
	context_pam2.responses = xmalloc(sizeof(struct pam_response) * num_msg);
	memset(context_pam2.responses, 0, sizeof(struct pam_response) * num_msg);

	packet_start(SSH2_MSG_USERAUTH_INFO_REQUEST);
	packet_put_cstring("");				/* Name */
	packet_put_cstring("");				/* Instructions */
	packet_put_cstring("");				/* Language */
	for (i = 0, j = 0; i < num_msg; i++) {
		if((PAM_MSG_MEMBER(msg, i, msg_style) == PAM_PROMPT_ECHO_ON) ||
		   (PAM_MSG_MEMBER(msg, i, msg_style) == PAM_PROMPT_ECHO_OFF) ||
		   (i == num_msg - 1)) {
			j++;
		}
	}
	packet_put_int(j);				/* Number of prompts. */
	context_pam2.num_expected = j;
	for (i = 0, j = 0; i < num_msg; i++) {
		switch(PAM_MSG_MEMBER(msg, i, msg_style)) {
			case PAM_PROMPT_ECHO_ON:
				echo = 1;
				break;
			case PAM_PROMPT_ECHO_OFF:
				echo = 0;
				break;
			default:
				echo = 0;
				break;
		}
		if(text) {
			tmp = xmalloc(strlen(text) + strlen(PAM_MSG_MEMBER(msg, i, msg)) + 2);
			strcpy(tmp, text);
			strcat(tmp, "\n");
			strcat(tmp, PAM_MSG_MEMBER(msg, i, msg));
			xfree(text);
			text = tmp;
			tmp = NULL;
		} else {
			text = xstrdup(PAM_MSG_MEMBER(msg, i, msg));
		}
		if((PAM_MSG_MEMBER(msg, i, msg_style) == PAM_PROMPT_ECHO_ON) ||
		   (PAM_MSG_MEMBER(msg, i, msg_style) == PAM_PROMPT_ECHO_OFF) ||
		   (i == num_msg - 1)) {
			debug("sending prompt ssh-%d(pam-%d) = \"%s\"",
			      j, i, text);
			context_pam2.prompts[j++] = i;
			packet_put_cstring(text);
			packet_put_char(echo);
			xfree(text);
			text = NULL;
		}
	}
	packet_send();
	packet_write_wait();

	/* Grabbing control of execution and spinning until we get what
	 * we want is probably rude, but it seems to work properly, and
	 * the client *should* be in lock-step with us, so the loop should
	 * only be traversed once. */
	while(context_pam2.finished == 0) {
		done = 1;
		dispatch_run(DISPATCH_BLOCK, &done, appdata_ptr);
		if(context_pam2.finished == 0) {
			debug("extra packet during conversation");
		}
	}

	if(context_pam2.num_received == context_pam2.num_expected) {
		*resp = context_pam2.responses;
		return PAM_SUCCESS;
	} else {
		return PAM_CONV_ERR;
	}
}

void
input_userauth_info_response_pam(int type, int plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	unsigned int nresp = 0, rlen = 0, i = 0;
	char *resp;

	if (authctxt == NULL)
		fatal("input_userauth_info_response_pam: no authentication context");

	if (authctxt->attempt++ >= AUTH_FAIL_MAX)
		packet_disconnect("too many failed userauth_requests");

	nresp = packet_get_int();	/* Number of responses. */
	debug("got %d responses", nresp);

	for (i = 0; i < nresp; i++) {
		int j = context_pam2.prompts[i];
		resp = packet_get_string(&rlen);
		debug("response ssh-%d(pam-%d) = \"%s\"", i, j, resp);
		context_pam2.responses[j].resp_retcode = PAM_SUCCESS;
		context_pam2.responses[j].resp = xstrdup(resp);
		xfree(resp);
		context_pam2.num_received++;
	}

	context_pam2.finished = 1;

	packet_done();
}

#endif
