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
 * Helper for session_channel_req_fuzz. Drives the server side of
 * session.c CHANNEL_REQUEST processing via the public
 * session_input_channel_req() entry point. See the .cc driver for
 * the threat-model writeup.
 */

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

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
#include "hostfile.h"
#include "auth.h"
#include "auth-options.h"
#include "servconf.h"
#include "channels.h"
#include "session.h"

ServerOptions options;
struct sshbuf *loginmsg = NULL;
struct include_list includes;
static struct sshauthopt g_auth_opts_storage;
struct sshauthopt *auth_opts = &g_auth_opts_storage;
struct passwd *privsep_pw = NULL;

static jmp_buf fuzz_env;
static volatile int in_fuzz = 0;

void
cleanup_exit(int code)
{
	if (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

void
__wrap_ssh_packet_disconnect(struct ssh *ssh, const char *fmt, ...)
{
	(void)ssh;
	(void)fmt;
	if (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

int
__wrap_sshpkt_fatal(struct ssh *ssh, int r, const char *fmt, ...)
{
	(void)ssh;
	(void)fmt;
	if (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

int
mm_is_monitor(void)
{
	return 0;
}

void
mm_audit_run_command(const char *cmd)
{
	(void)cmd;
}

int
mm_pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	if (namebuf != NULL && namebuflen > 0)
		namebuf[0] = '\0';
	return 0;
}

void mm_session_pty_cleanup2(Session *s) { (void)s; }
int platform_locked_account(struct passwd *pw) { (void)pw; return 0; }
void record_failed_login(struct ssh *ssh, const char *user,
    const char *hostname, const char *ttyname) { (void)ssh; (void)user;
    (void)hostname; (void)ttyname; }
int temporarily_use_uid(struct passwd *pw) { (void)pw; return 0; }
void restore_uid(void) { }
void platform_setusercontext(struct passwd *pw) { (void)pw; }
void platform_setusercontext_post_groups(struct passwd *pw) { (void)pw; }
struct connection_info *
server_get_connection_info(struct ssh *ssh, int populate, int use_dns)
    { (void)ssh; (void)populate; (void)use_dns; return NULL; }
int auth2_methods_valid(const char *list, int allow_unknown)
    { (void)list; (void)allow_unknown; return 0; }
struct sshbuf *cfg = NULL;
int auth_sock = -1;
char **tun_fwd_ifnames = NULL;

struct logininfo *login_get_lastlog(struct logininfo *li, const uid_t uid)
    { (void)li; (void)uid; return NULL; }
struct logininfo *login_alloc_entry(pid_t pid, const char *username,
    const char *hostname, const char *line)
    { (void)pid; (void)username; (void)hostname; (void)line; return NULL; }
void server_process_permitopen(struct ssh *ssh) { (void)ssh; }
int server_loop2(struct ssh *ssh, Authctxt *authctxt)
    { (void)ssh; (void)authctxt; return 0; }
int platform_privileged_uidswap(void) { return 0; }
int sftp_server_main(int argc, char **argv, struct passwd *user_pw)
    { (void)argc; (void)argv; (void)user_pw; return 0; }
int debug_flag = 0;
void permanently_set_uid(struct passwd *pw) { (void)pw; }
int login_login(struct logininfo *li) { (void)li; return 0; }
int login_logout(struct logininfo *li) { (void)li; return 0; }
void login_free_entry(struct logininfo *li) { (void)li; }
void login_set_addr(struct logininfo *li, const struct sockaddr *sa,
    const unsigned int sa_size) { (void)li; (void)sa; (void)sa_size; }
int openpty(int *amaster, int *aslave, char *name,
    const struct termios *termp, const struct winsize *winp)
    { (void)termp; (void)winp; *amaster = -1; *aslave = -1;
    if (name) name[0] = '\0'; return -1; }

extern int __real_do_exec(struct ssh *, Session *, const char *);
extern int __real_do_exec_pty(struct ssh *, Session *, const char *);
extern int __real_do_exec_no_pty(struct ssh *, Session *, const char *);

int
__wrap_do_exec(struct ssh *ssh, Session *s, const char *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	return 0;
}

int
__wrap_do_exec_pty(struct ssh *ssh, Session *s, const char *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	return 0;
}

int
__wrap_do_exec_no_pty(struct ssh *ssh, Session *s, const char *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	return 0;
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

#include "fixed-keys.h"

static struct ssh *g_client = NULL;
static struct ssh *g_server = NULL;
static int g_init = 0;
static int g_channel_id = -1;
static Authctxt g_authctxt;
static struct passwd g_fake_pw;

static char *g_pending_rtype = NULL;
static char *g_pending_exec_cmd = NULL;
static char *g_pending_env_name = NULL;
static char *g_pending_env_val = NULL;

static void
my_session_exec_req(struct ssh *ssh)
{
	int r;
	if ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

static void
my_session_env_req(struct ssh *ssh)
{
	int r;
	if ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

static int
input_channel_request(int type, uint32_t seq, struct ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(void)type;
	(void)seq;
	if (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, NULL) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		return 0;
	if (g_channel_id >= 0 && g_pending_rtype != NULL) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		if (c != NULL) {
			if (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			else if (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			else
				(void)session_input_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	return 0;
}

static void
reset_channel(struct ssh *ssh)
{
	if (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		if (c != NULL)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (char *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (char *)"fuzz", 0);
	if (c == NULL)
		return;
	g_channel_id = c->self;
	Session *s = session_new();
	if (s != NULL) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

static int
init_once(void)
{
	if (g_init)
		return 0;
	signal(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, sizeof(g_fake_pw));
	g_fake_pw.pw_name = (char *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (char *)"/tmp";
	g_fake_pw.pw_shell = (char *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, sizeof(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

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

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_MSG_CHANNEL_REQUEST,
	    &input_channel_request);

	free(keyname);
	for (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	g_init = 1;
	return 0;
}

void
fuzz_session_one(const uint8_t *data, size_t size)
{
	if (init_once() != 0)
		return;
	if (size > 65000)
		return;

	reset_channel(g_server);

	in_fuzz = 1;
	if (setjmp(fuzz_env) == 0) {
		size_t transferred;
		if (ssh_packet_put(g_client, SSH2_MSG_CHANNEL_REQUEST,
		    data, size) != 0)
			goto done;
		if (pump(g_client, g_server, &transferred) != 0)
			goto done;
		(void)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, NULL);
	done:
		;
	}
	in_fuzz = 0;
	free(g_pending_rtype);
	g_pending_rtype = NULL;
	free(g_pending_exec_cmd);
	g_pending_exec_cmd = NULL;
	free(g_pending_env_name);
	g_pending_env_name = NULL;
	free(g_pending_env_val);
	g_pending_env_val = NULL;
}
