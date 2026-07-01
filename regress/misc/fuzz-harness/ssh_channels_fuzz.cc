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
 * Fuzzer for OpenSSH channel dispatch (channels.c)
 *
 * Target: channels.c
 *
 * Drives the eight public channel_input_* handlers declared in
 * channels.h through ssh_dispatch. After an in-process KEX, a set of
 * scenarios is iterated for each fuzz input. Each scenario sets up a
 * fresh channel (varying type, starting state, and fd backing) with
 * dummy open_confirm and status_confirm callbacks registered, then
 * sequences the same fuzz body as nine CHANNEL_* message types in
 * realistic order so state machine transitions and callback paths
 * are exercised.
 *
 * Primary functions exercised:
 * - channel_input_data / extended_data / ieof / oclose
 * - channel_input_open_confirmation / open_failure
 * - channel_input_window_adjust / status_confirm
 * - channel state machine in nchan.c via sequenced messages
 *
 * Threat model: a peer SSH endpoint sending crafted CHANNEL_*
 * messages over an established session. Pre-auth attacker bytes
 * after KEX completes.
 *
 * Linker --wrap on ssh_packet_disconnect and sshpkt_fatal:
 * channel_input_* call those on malformed channel ids and similar
 * invariants. The real implementations free packet state before
 * cleanup_exit longjmp gets control; the wrappers longjmp directly
 * so per-iteration state survives.
 */

#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C" {
#include "includes.h"
#include "ssherr.h"
#include "ssh_api.h"
#include "sshbuf.h"
#include "packet.h"
#include "myproposal.h"
#include "kex.h"
#include "xmalloc.h"
#include "authfile.h"
#include "sshkey.h"
#include "log.h"
#include "ssh2.h"
#include "channels.h"
}


#include "fixed-keys.h"

static jmp_buf fuzz_env;
static volatile int in_fuzz = 0;

static char *g_open_failure_msg = NULL;

extern "C" int
my_channel_input_open_failure(int type, uint32_t seq, struct ssh *ssh)
{
	(void)type;
	(void)seq;
	uint32_t reason;
	int r;
	if ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	if ((r = sshpkt_get_cstring(ssh, &g_open_failure_msg, NULL)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, NULL, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	return 0;
}

extern "C" void
cleanup_exit(int code)
{
	if (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

extern "C" void
__wrap_ssh_packet_disconnect(struct ssh *ssh, const char *fmt, ...)
{
	(void)ssh;
	(void)fmt;
	if (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

extern "C" int
__wrap_sshpkt_fatal(struct ssh *ssh, int r, const char *fmt, ...)
{
	(void)ssh;
	(void)fmt;
	if (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
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

static struct ssh *g_client = NULL;
static struct ssh *g_server = NULL;
static int g_init = 0;
static int g_pipe[2] = { -1, -1 };

static void
dummy_open_confirm(struct ssh *ssh, int id, int success, void *ctx)
{
	(void)ssh;
	(void)id;
	(void)success;
	(void)ctx;
}

static void
dummy_status_confirm(struct ssh *ssh, int type, Channel *c, void *ctx)
{
	(void)ssh;
	(void)type;
	(void)c;
	(void)ctx;
}

static void
dummy_status_abandon(struct ssh *ssh, Channel *c, void *ctx)
{
	(void)ssh;
	(void)c;
	(void)ctx;
}

static int
init_once(void)
{
	if (g_init)
		return 0;
	signal(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	int pfd[2];
	if (pipe(pfd) != 0)
		return -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	if (g_pipe[0] < 0 || g_pipe[1] < 0)
		return -1;
	int fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	int fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(void)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(void)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

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

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_DATA,
	    &channel_input_data);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_EXTENDED_DATA,
	    &channel_input_extended_data);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_EOF,
	    &channel_input_ieof);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_CLOSE,
	    &channel_input_oclose);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_OPEN_CONFIRMATION,
	    &channel_input_open_confirmation);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_OPEN_FAILURE,
	    &my_channel_input_open_failure);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_WINDOW_ADJUST,
	    &channel_input_window_adjust);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_SUCCESS,
	    &channel_input_status_confirm);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_FAILURE,
	    &channel_input_status_confirm);

	free(keyname);
	for (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	g_init = 1;
	return 0;
}

struct chan_scenario {
	const char *ctype;
	int state;
	int use_pipe;
};

static const struct chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

static int g_channel_id = -1;

static void
drain_pipe(void)
{
	char buf[4096];
	if (g_pipe[0] < 0)
		return;
	while (read(g_pipe[0], buf, sizeof(buf)) > 0) { }
}

static void
reset_channel(struct ssh *ssh, const struct chan_scenario *s)
{
	if (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		if (c != NULL)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	int rfd = s->use_pipe ? g_pipe[1] : -1;
	int wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (char *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (char *)"fuzz", 0);
	if (c == NULL)
		return;
	g_channel_id = c->self;
	channel_register_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, NULL);
	channel_register_status_confirm(ssh, g_channel_id,
	    &dummy_status_confirm, &dummy_status_abandon, NULL);
}

static const uint8_t k_msg_types[] = {
	SSH2_MSG_CHANNEL_OPEN_CONFIRMATION,
	SSH2_MSG_CHANNEL_OPEN_FAILURE,
	SSH2_MSG_CHANNEL_WINDOW_ADJUST,
	SSH2_MSG_CHANNEL_DATA,
	SSH2_MSG_CHANNEL_EXTENDED_DATA,
	SSH2_MSG_CHANNEL_SUCCESS,
	SSH2_MSG_CHANNEL_FAILURE,
	SSH2_MSG_CHANNEL_EOF,
	SSH2_MSG_CHANNEL_CLOSE,
};

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (init_once() != 0)
		return 0;
	if (size > 65000)
		return 0;

	const size_t n_scen = sizeof(k_scenarios) / sizeof(k_scenarios[0]);
	const size_t n_msg = sizeof(k_msg_types) / sizeof(k_msg_types[0]);

	for (size_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		for (size_t t = 0; t < n_msg; t++) {
			in_fuzz = 1;
			if (setjmp(fuzz_env) == 0) {
				size_t transferred;
				if (ssh_packet_put(g_server, k_msg_types[t],
				    data, size) != 0)
					goto done;
				if (pump(g_server, g_client,
				    &transferred) != 0)
					goto done;
				(void)ssh_dispatch_run(g_client,
				    DISPATCH_NONBLOCK, NULL);
			done:
				;
			}
			in_fuzz = 0;
			free(g_open_failure_msg);
			g_open_failure_msg = NULL;
		}
	}
	return 0;
}
