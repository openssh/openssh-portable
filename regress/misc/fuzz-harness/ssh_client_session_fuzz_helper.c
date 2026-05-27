/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for OpenSSH client-side userauth dispatch (sshconnect2.c)
 *
 * Target: sshconnect2.c
 *
 * Follows the agent_fuzz_helper.c pattern: #include's sshconnect2.c so
 * its static input_userauth_* handlers are reachable from this
 * translation unit. The driver completes an in-process KEX with real
 * cipher and HMAC, then for each iteration injects a fuzzer-controlled
 * SSH2_MSG_* message into the client's input stream and runs the
 * dispatch loop. Non-userauth message types fall through to
 * dispatch_protocol_ignore.
 *
 * Primary functions exercised:
 * - input_userauth_banner / failure / success / info_req / pk_ok /
 *   passwd_changereq / service_accept
 * - sshkey_from_blob (via input_userauth_pk_ok)
 * - downstream sshpkt_get_* and sshbuf_get_* primitives
 *
 * Linker --wrap neutralises two blocking functions:
 * - __wrap_ssh_packet_write_wait (real one ppoll's on fd=-1)
 * - __wrap_read_passphrase (real one reads /dev/tty)
 */

#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "digest.h"
#include "misc.h"
#include "ssh.h"
#include "ssh2.h"
#include "ssh_api.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "packet.h"
#include "myproposal.h"
#include "kex.h"
#include "xmalloc.h"
#include "authfile.h"
#include "readconf.h"

Options options;
int debug_flag = 0;

struct ssh;

int
__wrap_ssh_packet_write_wait(struct ssh *ssh)
{
	(void)ssh;
	return 0;
}

char *
__wrap_read_passphrase(const char *prompt, int flags)
{
	(void)prompt;
	(void)flags;
	return strdup("fuzz");
}

#include "../../../sshconnect2.c"
#include "fixed-keys.h"

static jmp_buf fuzz_env;
static volatile int in_fuzz = 0;

void
cleanup_exit(int code)
{
	if (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

static struct sshkey *
load_private(const char *str)
{
	struct sshbuf *b = sshbuf_from(str, strlen(str));
	struct sshkey *k = NULL;
	if (b == NULL || sshkey_parse_private_fileblob(b, "", &k, NULL) != 0)
		abort();
	sshbuf_free(b);
	return k;
}

static struct sshkey *
load_public(const char *str)
{
	char *tmp, *cp;
	struct sshkey *k = sshkey_new(KEY_UNSPEC);
	if (k == NULL)
		abort();
	tmp = cp = strdup(str);
	if (sshkey_read(k, &cp) != 0)
		abort();
	free(tmp);
	return k;
}

static int
pump(struct ssh *from, struct ssh *to, size_t *transferred)
{
	const u_char *buf;
	size_t len;
	u_char type;
	int r;
	*transferred = 0;
	if ((r = ssh_packet_next(from, &type)) != 0)
		return r;
	buf = ssh_output_ptr(from, &len);
	if (len == 0)
		return 0;
	if ((r = ssh_input_append(to, buf, len)) != 0)
		return r;
	if ((r = ssh_output_consume(from, len)) != 0)
		return r;
	*transferred = len;
	return 0;
}

static int
run_kex(struct ssh *client, struct ssh *server)
{
	int r;
	size_t cn, sn;
	for (int i = 0; i < 100; i++) {
		if ((r = pump(server, client, &sn)) != 0) return r;
		if ((r = pump(client, server, &cn)) != 0) return r;
		if (server->kex->done && client->kex->done)
			return 0;
		if (cn == 0 && sn == 0)
			return SSH_ERR_PROTOCOL_ERROR;
	}
	return SSH_ERR_PROTOCOL_ERROR;
}

static Sensitive g_sensitive = { NULL, 0 };
static Authctxt g_authctxt;
static struct ssh *g_client = NULL;
static struct ssh *g_server = NULL;
static int g_init = 0;

static void
fuzz_reset_authctxt(struct ssh *ssh)
{
	free(g_authctxt.authlist);
	g_authctxt.authlist = NULL;
	if (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, sizeof(g_authctxt));
	g_authctxt.server_user = (char *)"fuzz";
	g_authctxt.local_user = (char *)"fuzz";
	g_authctxt.host = (char *)"127.0.0.1";
	g_authctxt.service = (char *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.method = authmethod_lookup("none");
	g_authctxt.authlist = NULL;
	g_authctxt.methoddata = NULL;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.active_ktype = NULL;
	g_authctxt.oktypes = NULL;
	g_authctxt.ktypes = NULL;
	g_authctxt.info_req_seen = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.keys);
	ssh->authctxt = &g_authctxt;
}

static void
fuzz_setup(struct ssh *ssh)
{
	initialize_options(&options);
	options.batch_mode = 1;
	options.pubkey_authentication = 0;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
	options.hostbased_authentication = 0;
	options.gss_authentication = 0;
	options.preferred_authentications = strdup("none");
	options.user = strdup("fuzz");
	options.number_of_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(void)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, kex_input_ext_info);
	ssh_dispatch_set(ssh, SSH2_MSG_SERVICE_ACCEPT, &input_userauth_service_accept);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_SUCCESS, &input_userauth_success);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_FAILURE, &input_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_BANNER, &input_userauth_banner);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_REQUEST, &input_userauth_info_req);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_PK_OK, &input_userauth_pk_ok);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ, &input_userauth_passwd_changereq);
}

static int
init_once(void)
{
	if (g_init)
		return 0;
	signal(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	struct sshkey *priv = load_private(PRIV_ED25519);
	struct sshkey *pub = load_public(PUB_ED25519);
	char *keyname = xstrdup(sshkey_ssh_name(priv));

	const char *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	char *proposal[PROPOSAL_MAX] = { 0 };
	int i;
	for (i = 0; i < PROPOSAL_MAX; i++) {
		const char *p = defaults[i];
		if (i == PROPOSAL_SERVER_HOST_KEY_ALGS)
			p = keyname;
		else if (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		else if (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		else if (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	struct kex_params kp;
	memcpy(kp.proposal, proposal, sizeof(proposal));

	if (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		return -1;
	if (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		return -1;
	if (run_kex(g_client, g_server) != 0)
		return -1;

	fuzz_setup(g_client);

	free(keyname);
	for (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	g_init = 1;
	return 0;
}

static const uint8_t k_msg_types[] = {
	SSH2_MSG_DISCONNECT, SSH2_MSG_IGNORE, SSH2_MSG_UNIMPLEMENTED,
	SSH2_MSG_DEBUG, SSH2_MSG_SERVICE_ACCEPT, SSH2_MSG_EXT_INFO,
	SSH2_MSG_USERAUTH_FAILURE, SSH2_MSG_USERAUTH_SUCCESS,
	SSH2_MSG_USERAUTH_BANNER, SSH2_MSG_USERAUTH_INFO_REQUEST,
	SSH2_MSG_USERAUTH_PK_OK, SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ,
};

void
fuzz_one_message(const uint8_t *data, size_t size)
{
	if (init_once() != 0)
		return;
	if (size > 65000)
		return;

	uint8_t selector = size > 0 ? data[0] : 0;
	const uint8_t *payload = size > 0 ? data + 1 : NULL;
	size_t plen = size > 0 ? size - 1 : 0;

	uint8_t msg_type = k_msg_types[selector %
	    (sizeof(k_msg_types) / sizeof(k_msg_types[0]))];

	fuzz_reset_authctxt(g_client);

	in_fuzz = 1;
	if (setjmp(fuzz_env) == 0) {
		size_t transferred;
		if (ssh_packet_put(g_server, msg_type, payload, plen) != 0)
			goto done;
		if (pump(g_server, g_client, &transferred) != 0)
			goto done;
		(void)ssh_dispatch_run(g_client, DISPATCH_NONBLOCK, NULL);
	done:
		;
	}
	in_fuzz = 0;
}
