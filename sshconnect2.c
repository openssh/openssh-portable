/* $OpenBSD: sshconnect2.c,v 1.210 2014/07/15 15:54:14 millert Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Damien Miller.  All rights reserved.
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
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#if defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#include <vis.h>
#endif

#include "openbsd-compat/sys-queue.h"

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "buffer.h"
#include "packet.h"
#include "compat.h"
#include "cipher.h"
#include "key.h"
#include "kex.h"
#include "myproposal.h"
#include "sshconnect.h"
#include "authfile.h"
#include "dh.h"
#include "authfd.h"
#include "log.h"
#include "misc.h"
#include "readconf.h"
#include "match.h"
#include "dispatch.h"
#include "canohost.h"
#include "msg.h"
#include "pathnames.h"
#include "uidswap.h"
#include "hostfile.h"

#ifdef GSSAPI
#include "ssh-gss.h"
#endif

/* import */
extern char *client_version_string;
extern char *server_version_string;
extern Options options;

/*
 * SSH2 key exchange
 */

u_char *session_id2 = NULL;
u_int session_id2_len = 0;

char *xxx_host;
struct sockaddr *xxx_hostaddr;

Kex *xxx_kex = NULL;

static int
verify_host_key_callback(Key *hostkey)
{
	if (verify_host_key(xxx_host, xxx_hostaddr, hostkey) == -1)
		fatal("Host key verification failed.");
	return 0;
}

static char *
order_hostkeyalgs(char *host, struct sockaddr *hostaddr, u_short port)
{
	char *oavail, *avail, *first, *last, *alg, *hostname, *ret;
	size_t maxlen;
	struct hostkeys *hostkeys;
	int ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, NULL);
	hostkeys = init_hostkeys();
	for (i = 0; i < options.num_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, NULL, options.user_hostfiles[i]);
	for (i = 0; i < options.num_system_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, NULL, options.system_hostfiles[i]);

	oavail = avail = xstrdup(KEX_DEFAULT_PK_ALG);
	maxlen = strlen(avail) + 1;
	first = xmalloc(maxlen);
	last = xmalloc(maxlen);
	*first = *last = '\0';

#define ALG_APPEND(to, from) \
	do { \
		if (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} while (0)

	while ((alg = strsep(&avail, ",")) && *alg != '\0') {
		if ((ktype = key_type_from_name(alg)) == KEY_UNSPEC)
			fatal("%s: unknown alg %s", __func__, alg);
		if (lookup_key_in_hostkeys_by_type(hostkeys,
		    key_type_plain(ktype), NULL))
			ALG_APPEND(first, alg);
		else
			ALG_APPEND(last, alg);
	}
#undef ALG_APPEND
	xasprintf(&ret, "%s%s%s", first, *first == '\0' ? "" : ",", last);
	if (*first != '\0')
		debug3("%s: prefer hostkeyalgs: %s", __func__, first);

	free(first);
	free(last);
	free(hostname);
	free(oavail);
	free_hostkeys(hostkeys);

	return ret;
}

void
ssh_kex2(char *host, struct sockaddr *hostaddr, u_short port)
{
	char *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	Kex *kex;

	xxx_host = host;
	xxx_hostaddr = hostaddr;

	if (options.ciphers == (char *)-1) {
		logit("No valid ciphers for protocol version 2 given, using defaults.");
		options.ciphers = NULL;
	}
	if (options.ciphers != NULL) {
		myproposal[PROPOSAL_ENC_ALGS_CTOS] =
		myproposal[PROPOSAL_ENC_ALGS_STOC] = options.ciphers;
	}
	myproposal[PROPOSAL_ENC_ALGS_CTOS] =
	    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_CTOS]);
	myproposal[PROPOSAL_ENC_ALGS_STOC] =
	    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_STOC]);
	if (options.compression) {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
		myproposal[PROPOSAL_COMP_ALGS_STOC] = "zlib@openssh.com,zlib,none";
	} else {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
		myproposal[PROPOSAL_COMP_ALGS_STOC] = "none,zlib@openssh.com,zlib";
	}
	if (options.macs != NULL) {
		myproposal[PROPOSAL_MAC_ALGS_CTOS] =
		myproposal[PROPOSAL_MAC_ALGS_STOC] = options.macs;
	}
	if (options.hostkeyalgorithms != NULL)
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] =
		    compat_pkalg_proposal(options.hostkeyalgorithms);
	else {
		/* Prefer algorithms that we already have keys for */
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] =
		    compat_pkalg_proposal(
		    order_hostkeyalgs(host, hostaddr, port));
	}
	if (options.kex_algorithms != NULL)
		myproposal[PROPOSAL_KEX_ALGS] = options.kex_algorithms;
	myproposal[PROPOSAL_KEX_ALGS] = compat_kex_proposal(
	    myproposal[PROPOSAL_KEX_ALGS]);

	if (options.rekey_limit || options.rekey_interval)
		packet_set_rekey_limits((u_int32_t)options.rekey_limit,
		    (time_t)options.rekey_interval);

	/* start key exchange */
	kex = kex_setup(myproposal);
#ifdef WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kexdh_client;
	kex->kex[KEX_DH_GRP14_SHA1] = kexdh_client;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	kex->kex[KEX_ECDH_SHA2] = kexecdh_client;
#endif
	kex->kex[KEX_C25519_SHA256] = kexc25519_client;
	kex->client_version_string=client_version_string;
	kex->server_version_string=server_version_string;
	kex->verify_host_key=&verify_host_key_callback;

	xxx_kex = kex;

	dispatch_run(DISPATCH_BLOCK, &kex->done, kex);

	if (options.use_roaming && !kex->roaming) {
		debug("Roaming not allowed by server");
		options.use_roaming = 0;
	}

	session_id2 = kex->session_id;
	session_id2_len = kex->session_id_len;

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	packet_start(SSH2_MSG_IGNORE);
	packet_put_cstring("markus");
	packet_send();
	packet_write_wait();
#endif
}

/*
 * Authenticate user
 */

typedef struct Authctxt Authctxt;
typedef struct Authmethod Authmethod;
typedef struct identity Identity;
typedef struct idlist Idlist;

struct identity {
	TAILQ_ENTRY(identity) next;
	AuthenticationConnection *ac;	/* set if agent supports key */
	Key	*key;			/* public/private key */
	char	*filename;		/* comment for agent-only keys */
	int	tried;
	int	isprivate;		/* key points to the private key */
	int	userprovided;
};
TAILQ_HEAD(idlist, identity);

struct Authctxt {
	const char *server_user;
	const char *local_user;
	const char *host;
	const char *service;
	Authmethod *method;
	sig_atomic_t success;
	char *authlist;
	/* pubkey */
	Idlist keys;
	AuthenticationConnection *agent;
	/* hostbased */
	Sensitive *sensitive;
	/* kbd-interactive */
	int info_req_seen;
	/* generic */
	void *methoddata;
};
struct Authmethod {
	char	*name;		/* string to compare against server's list */
	int	(*userauth)(Authctxt *authctxt);
	void	(*cleanup)(Authctxt *authctxt);
	int	*enabled;	/* flag in option struct that enables method */
	int	*batch_flag;	/* flag in option struct that disables method */
};

void	input_userauth_success(int, u_int32_t, void *);
void	input_userauth_success_unexpected(int, u_int32_t, void *);
void	input_userauth_failure(int, u_int32_t, void *);
void	input_userauth_banner(int, u_int32_t, void *);
void	input_userauth_error(int, u_int32_t, void *);
void	input_userauth_info_req(int, u_int32_t, void *);
void	input_userauth_pk_ok(int, u_int32_t, void *);
void	input_userauth_passwd_changereq(int, u_int32_t, void *);

int	userauth_none(Authctxt *);
int	userauth_pubkey(Authctxt *);
int	userauth_passwd(Authctxt *);
int	userauth_kbdint(Authctxt *);
int	userauth_hostbased(Authctxt *);

#ifdef GSSAPI
int	userauth_gssapi(Authctxt *authctxt);
void	input_gssapi_response(int type, u_int32_t, void *);
void	input_gssapi_token(int type, u_int32_t, void *);
void	input_gssapi_hash(int type, u_int32_t, void *);
void	input_gssapi_error(int, u_int32_t, void *);
void	input_gssapi_errtok(int, u_int32_t, void *);
#endif

void	userauth(Authctxt *, char *);

static int sign_and_send_pubkey(Authctxt *, Identity *);
static void pubkey_prepare(Authctxt *);
static void pubkey_cleanup(Authctxt *);
static Key *load_identity_file(char *, int);

static Authmethod *authmethod_get(char *authlist);
static Authmethod *authmethod_lookup(const char *name);
static char *authmethods_get(void);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		NULL,
		&options.gss_authentication,
		NULL},
#endif
	{"hostbased",
		userauth_hostbased,
		NULL,
		&options.hostbased_authentication,
		NULL},
	{"publickey",
		userauth_pubkey,
		NULL,
		&options.pubkey_authentication,
		NULL},
	{"keyboard-interactive",
		userauth_kbdint,
		NULL,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		NULL,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		NULL,
		NULL,
		NULL},
	{NULL, NULL, NULL, NULL, NULL}
};

void
ssh_userauth2(const char *local_user, const char *server_user, char *host,
    Sensitive *sensitive)
{
	Authctxt authctxt;
	int type;

	if (options.challenge_response_authentication)
		options.kbd_interactive_authentication = 1;

	packet_start(SSH2_MSG_SERVICE_REQUEST);
	packet_put_cstring("ssh-userauth");
	packet_send();
	debug("SSH2_MSG_SERVICE_REQUEST sent");
	packet_write_wait();
	type = packet_read();
	if (type != SSH2_MSG_SERVICE_ACCEPT)
		fatal("Server denied authentication request: %d", type);
	if (packet_remaining() > 0) {
		char *reply = packet_get_string(NULL);
		debug2("service_accept: %s", reply);
		free(reply);
	} else {
		debug2("buggy server: service_accept w/o service");
	}
	packet_check_eom();
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	if (options.preferred_authentications == NULL)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, sizeof(authctxt));
	pubkey_prepare(&authctxt);
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = NULL;
	authctxt.methoddata = NULL;
	authctxt.sensitive = sensitive;
	authctxt.info_req_seen = 0;
	if (authctxt.method == NULL)
		fatal("ssh_userauth2: internal error: cannot send userauth none request");

	/* initial userauth request */
	userauth_none(&authctxt);

	dispatch_init(&input_userauth_error);
	dispatch_set(SSH2_MSG_USERAUTH_SUCCESS, &input_userauth_success);
	dispatch_set(SSH2_MSG_USERAUTH_FAILURE, &input_userauth_failure);
	dispatch_set(SSH2_MSG_USERAUTH_BANNER, &input_userauth_banner);
	dispatch_run(DISPATCH_BLOCK, &authctxt.success, &authctxt);	/* loop until success */

	pubkey_cleanup(&authctxt);
	dispatch_range(SSH2_MSG_USERAUTH_MIN, SSH2_MSG_USERAUTH_MAX, NULL);

	debug("Authentication succeeded (%s).", authctxt.method->name);
}

void
userauth(Authctxt *authctxt, char *authlist)
{
	if (authctxt->method != NULL && authctxt->method->cleanup != NULL)
		authctxt->method->cleanup(authctxt);

	free(authctxt->methoddata);
	authctxt->methoddata = NULL;
	if (authlist == NULL) {
		authlist = authctxt->authlist;
	} else {
		free(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	for (;;) {
		Authmethod *method = authmethod_get(authlist);
		if (method == NULL)
			fatal("Permission denied (%s).", authlist);
		authctxt->method = method;

		/* reset the per method handler */
		dispatch_range(SSH2_MSG_USERAUTH_PER_METHOD_MIN,
		    SSH2_MSG_USERAUTH_PER_METHOD_MAX, NULL);

		/* and try new method */
		if (method->userauth(authctxt) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			break;
		} else {
			debug2("we did not send a packet, disable method");
			method->enabled = NULL;
		}
	}
}

/* ARGSUSED */
void
input_userauth_error(int type, u_int32_t seq, void *ctxt)
{
	fatal("input_userauth_error: bad message during authentication: "
	    "type %d", type);
}

/* ARGSUSED */
void
input_userauth_banner(int type, u_int32_t seq, void *ctxt)
{
	char *msg, *raw, *lang;
	u_int len;

	debug3("input_userauth_banner");
	raw = packet_get_string(&len);
	lang = packet_get_string(NULL);
	if (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO) {
		if (len > 65536)
			len = 65536;
		msg = xmalloc(len * 4 + 1); /* max expansion from strnvis() */
		strnvis(msg, raw, len * 4 + 1, VIS_SAFE|VIS_OCTAL|VIS_NOSLASH);
		fprintf(stderr, "%s", msg);
		free(msg);
	}
	free(raw);
	free(lang);
}

/* ARGSUSED */
void
input_userauth_success(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;

	if (authctxt == NULL)
		fatal("input_userauth_success: no authentication context");
	free(authctxt->authlist);
	authctxt->authlist = NULL;
	if (authctxt->method != NULL && authctxt->method->cleanup != NULL)
		authctxt->method->cleanup(authctxt);
	free(authctxt->methoddata);
	authctxt->methoddata = NULL;
	authctxt->success = 1;			/* break out */
}

void
input_userauth_success_unexpected(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;

	if (authctxt == NULL)
		fatal("%s: no authentication context", __func__);

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
}

/* ARGSUSED */
void
input_userauth_failure(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	char *authlist = NULL;
	int partial;

	if (authctxt == NULL)
		fatal("input_userauth_failure: no authentication context");

	authlist = packet_get_string(NULL);
	partial = packet_get_char();
	packet_check_eom();

	if (partial != 0) {
		logit("Authenticated with partial success.");
		/* reset state */
		pubkey_cleanup(authctxt);
		pubkey_prepare(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(authctxt, authlist);
}

/* ARGSUSED */
void
input_userauth_pk_ok(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Key *key = NULL;
	Identity *id = NULL;
	Buffer b;
	int pktype, sent = 0;
	u_int alen, blen;
	char *pkalg, *fp;
	u_char *pkblob;

	if (authctxt == NULL)
		fatal("input_userauth_pk_ok: no authentication context");
	if (datafellows & SSH_BUG_PKOK) {
		/* this is similar to SSH_BUG_PKAUTH */
		debug2("input_userauth_pk_ok: SSH_BUG_PKOK");
		pkblob = packet_get_string(&blen);
		buffer_init(&b);
		buffer_append(&b, pkblob, blen);
		pkalg = buffer_get_string(&b, &alen);
		buffer_free(&b);
	} else {
		pkalg = packet_get_string(&alen);
		pkblob = packet_get_string(&blen);
	}
	packet_check_eom();

	debug("Server accepts key: pkalg %s blen %u", pkalg, blen);

	if ((pktype = key_type_from_name(pkalg)) == KEY_UNSPEC) {
		debug("unknown pkalg %s", pkalg);
		goto done;
	}
	if ((key = key_from_blob(pkblob, blen)) == NULL) {
		debug("no key from blob. pkalg %s", pkalg);
		goto done;
	}
	if (key->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    key->type, pktype);
		goto done;
	}
	fp = key_fingerprint(key, SSH_FP_MD5, SSH_FP_HEX);
	debug2("input_userauth_pk_ok: fp %s", fp);
	free(fp);

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->keys, idlist, next) {
		if (key_equal(key, id->key)) {
			sent = sign_and_send_pubkey(authctxt, id);
			break;
		}
	}
done:
	if (key != NULL)
		key_free(key);
	free(pkalg);
	free(pkblob);

	/* try another method if we did not send a packet */
	if (sent == 0)
		userauth(authctxt, NULL);
}

#ifdef GSSAPI
int
userauth_gssapi(Authctxt *authctxt)
{
	Gssctxt *gssctxt = NULL;
	static gss_OID_set gss_supported = NULL;
	static u_int mech = 0;
	OM_uint32 min;
	int ok = 0;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	if (gss_supported == NULL)
		gss_indicate_mechs(&min, &gss_supported);

	/* Check to see if the mechanism is usable before we offer it */
	while (mech < gss_supported->count && !ok) {
		/* My DER encoding requires length<128 */
		if (gss_supported->elements[mech].length < 128 &&
		    ssh_gssapi_check_mechanism(&gssctxt, 
		    &gss_supported->elements[mech], authctxt->host)) {
			ok = 1; /* Mechanism works */
		} else {
			mech++;
		}
	}

	if (!ok)
		return 0;

	authctxt->methoddata=(void *)gssctxt;

	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);

	packet_put_int(1);

	packet_put_int((gss_supported->elements[mech].length) + 2);
	packet_put_char(SSH_GSS_OIDTYPE);
	packet_put_char(gss_supported->elements[mech].length);
	packet_put_raw(gss_supported->elements[mech].elements,
	    gss_supported->elements[mech].length);

	packet_send();

	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_RESPONSE, &input_gssapi_response);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, &input_gssapi_token);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERROR, &input_gssapi_error);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, &input_gssapi_errtok);

	mech++; /* Move along to next candidate */

	return 1;
}

static OM_uint32
process_gssapi_token(void *ctxt, gss_buffer_t recv_tok)
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	OM_uint32 status, ms, flags;
	Buffer b;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	if (send_tok.length > 0) {
		if (GSS_ERROR(status))
			packet_start(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK);
		else
			packet_start(SSH2_MSG_USERAUTH_GSSAPI_TOKEN);

		packet_put_string(send_tok.value, send_tok.length);
		packet_send();
		gss_release_buffer(&ms, &send_tok);
	}

	if (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		if (!(flags & GSS_C_INTEG_FLAG)) {
			packet_start(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE);
			packet_send();
		} else {
			ssh_gssapi_buildmic(&b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic");

			gssbuf.value = buffer_ptr(&b);
			gssbuf.length = buffer_len(&b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			if (!GSS_ERROR(status)) {
				packet_start(SSH2_MSG_USERAUTH_GSSAPI_MIC);
				packet_put_string(mic.value, mic.length);

				packet_send();
			}

			buffer_free(&b);
			gss_release_buffer(&ms, &mic);
		}
	}

	return status;
}

/* ARGSUSED */
void
input_gssapi_response(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
	int oidlen;
	char *oidv;

	if (authctxt == NULL)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	oidv = packet_get_string(&oidlen);

	if (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		free(oidv);
		debug("Badly encoded mechanism OID received");
		userauth(authctxt, NULL);
		return;
	}

	if (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	packet_check_eom();

	free(oidv);

	if (GSS_ERROR(process_gssapi_token(ctxt, GSS_C_NO_BUFFER))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(authctxt, NULL);
		return;
	}
}

/* ARGSUSED */
void
input_gssapi_token(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	gss_buffer_desc recv_tok;
	OM_uint32 status;
	u_int slen;

	if (authctxt == NULL)
		fatal("input_gssapi_response: no authentication context");

	recv_tok.value = packet_get_string(&slen);
	recv_tok.length = slen;	/* safe typecast */

	packet_check_eom();

	status = process_gssapi_token(ctxt, &recv_tok);

	free(recv_tok.value);

	if (GSS_ERROR(status)) {
		/* Start again with the next method in the list */
		userauth(authctxt, NULL);
		return;
	}
}

/* ARGSUSED */
void
input_gssapi_errtok(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 ms;
	u_int len;

	if (authctxt == NULL)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	recv_tok.value = packet_get_string(&len);
	recv_tok.length = len;

	packet_check_eom();

	/* Stick it into GSSAPI and see what it says */
	(void)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, NULL);

	free(recv_tok.value);
	gss_release_buffer(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
}

/* ARGSUSED */
void
input_gssapi_error(int type, u_int32_t plen, void *ctxt)
{
	char *msg;
	char *lang;

	/* maj */(void)packet_get_int();
	/* min */(void)packet_get_int();
	msg=packet_get_string(NULL);
	lang=packet_get_string(NULL);

	packet_check_eom();

	debug("Server GSSAPI Error:\n%s", msg);
	free(msg);
	free(lang);
}
#endif /* GSSAPI */

int
userauth_none(Authctxt *authctxt)
{
	/* initial userauth request */
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_send();
	return 1;
}

int
userauth_passwd(Authctxt *authctxt)
{
	static int attempt = 0;
	char prompt[150];
	char *password;
	const char *host = options.host_key_alias ?  options.host_key_alias :
	    authctxt->host;

	if (attempt++ >= options.number_of_password_prompts)
		return 0;

	if (attempt != 1)
		error("Permission denied, please try again.");

	snprintf(prompt, sizeof(prompt), "%.30s@%.128s's password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_put_char(0);
	packet_put_cstring(password);
	explicit_bzero(password, strlen(password));
	free(password);
	packet_add_padding(64);
	packet_send();

	dispatch_set(SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ,
	    &input_userauth_passwd_changereq);

	return 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
/* ARGSUSED */
void
input_userauth_passwd_changereq(int type, u_int32_t seqnr, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	char *info, *lang, *password = NULL, *retype = NULL;
	char prompt[150];
	const char *host = options.host_key_alias ? options.host_key_alias :
	    authctxt->host;

	debug2("input_userauth_passwd_changereq");

	if (authctxt == NULL)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");

	info = packet_get_string(NULL);
	lang = packet_get_string(NULL);
	if (strlen(info) > 0)
		logit("%s", info);
	free(info);
	free(lang);
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_put_char(1);			/* additional info */
	snprintf(prompt, sizeof(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	packet_put_cstring(password);
	explicit_bzero(password, strlen(password));
	free(password);
	password = NULL;
	while (password == NULL) {
		snprintf(prompt, sizeof(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		if (password == NULL) {
			/* bail out */
			return;
		}
		snprintf(prompt, sizeof(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		if (strcmp(password, retype) != 0) {
			explicit_bzero(password, strlen(password));
			free(password);
			logit("Mismatch; try again, EOF to quit.");
			password = NULL;
		}
		explicit_bzero(retype, strlen(retype));
		free(retype);
	}
	packet_put_cstring(password);
	explicit_bzero(password, strlen(password));
	free(password);
	packet_add_padding(64);
	packet_send();

	dispatch_set(SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ,
	    &input_userauth_passwd_changereq);
}

static int
identity_sign(Identity *id, u_char **sigp, u_int *lenp,
    u_char *data, u_int datalen)
{
	Key *prv;
	int ret;

	/* the agent supports this key */
	if (id->ac)
		return (ssh_agent_sign(id->ac, id->key, sigp, lenp,
		    data, datalen));
	/*
	 * we have already loaded the private key or
	 * the private key is stored in external hardware
	 */
	if (id->isprivate || (id->key->flags & SSHKEY_FLAG_EXT))
		return (key_sign(id->key, sigp, lenp, data, datalen));
	/* load the private key from the file */
	if ((prv = load_identity_file(id->filename, id->userprovided)) == NULL)
		return (-1);
	ret = key_sign(prv, sigp, lenp, data, datalen);
	key_free(prv);
	return (ret);
}

static int
sign_and_send_pubkey(Authctxt *authctxt, Identity *id)
{
	Buffer b;
	u_char *blob, *signature;
	u_int bloblen, slen;
	u_int skip = 0;
	int ret = -1;
	int have_sig = 1;
	char *fp;

	fp = key_fingerprint(id->key, SSH_FP_MD5, SSH_FP_HEX);
	debug3("sign_and_send_pubkey: %s %s", key_type(id->key), fp);
	free(fp);

	if (key_to_blob(id->key, &blob, &bloblen) == 0) {
		/* we cannot handle this key */
		debug3("sign_and_send_pubkey: cannot handle key");
		return 0;
	}
	/* data to be signed */
	buffer_init(&b);
	if (datafellows & SSH_OLD_SESSIONID) {
		buffer_append(&b, session_id2, session_id2_len);
		skip = session_id2_len;
	} else {
		buffer_put_string(&b, session_id2, session_id2_len);
		skip = buffer_len(&b);
	}
	buffer_put_char(&b, SSH2_MSG_USERAUTH_REQUEST);
	buffer_put_cstring(&b, authctxt->server_user);
	buffer_put_cstring(&b,
	    datafellows & SSH_BUG_PKSERVICE ?
	    "ssh-userauth" :
	    authctxt->service);
	if (datafellows & SSH_BUG_PKAUTH) {
		buffer_put_char(&b, have_sig);
	} else {
		buffer_put_cstring(&b, authctxt->method->name);
		buffer_put_char(&b, have_sig);
		buffer_put_cstring(&b, key_ssh_name(id->key));
	}
	buffer_put_string(&b, blob, bloblen);

	/* generate signature */
	ret = identity_sign(id, &signature, &slen,
	    buffer_ptr(&b), buffer_len(&b));
	if (ret == -1) {
		free(blob);
		buffer_free(&b);
		return 0;
	}
#ifdef DEBUG_PK
	buffer_dump(&b);
#endif
	if (datafellows & SSH_BUG_PKSERVICE) {
		buffer_clear(&b);
		buffer_append(&b, session_id2, session_id2_len);
		skip = session_id2_len;
		buffer_put_char(&b, SSH2_MSG_USERAUTH_REQUEST);
		buffer_put_cstring(&b, authctxt->server_user);
		buffer_put_cstring(&b, authctxt->service);
		buffer_put_cstring(&b, authctxt->method->name);
		buffer_put_char(&b, have_sig);
		if (!(datafellows & SSH_BUG_PKAUTH))
			buffer_put_cstring(&b, key_ssh_name(id->key));
		buffer_put_string(&b, blob, bloblen);
	}
	free(blob);

	/* append signature */
	buffer_put_string(&b, signature, slen);
	free(signature);

	/* skip session id and packet type */
	if (buffer_len(&b) < skip + 1)
		fatal("userauth_pubkey: internal error");
	buffer_consume(&b, skip + 1);

	/* put remaining data from buffer into packet */
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_raw(buffer_ptr(&b), buffer_len(&b));
	buffer_free(&b);
	packet_send();

	return 1;
}

static int
send_pubkey_test(Authctxt *authctxt, Identity *id)
{
	u_char *blob;
	u_int bloblen, have_sig = 0;

	debug3("send_pubkey_test");

	if (key_to_blob(id->key, &blob, &bloblen) == 0) {
		/* we cannot handle this key */
		debug3("send_pubkey_test: cannot handle key");
		return 0;
	}
	/* register callback for USERAUTH_PK_OK message */
	dispatch_set(SSH2_MSG_USERAUTH_PK_OK, &input_userauth_pk_ok);

	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_put_char(have_sig);
	if (!(datafellows & SSH_BUG_PKAUTH))
		packet_put_cstring(key_ssh_name(id->key));
	packet_put_string(blob, bloblen);
	free(blob);
	packet_send();
	return 1;
}

static Key *
load_identity_file(char *filename, int userprovided)
{
	Key *private;
	char prompt[300], *passphrase;
	int perm_ok = 0, quit, i;
	struct stat st;

	if (stat(filename, &st) < 0) {
		(userprovided ? logit : debug3)("no such identity: %s: %s",
		    filename, strerror(errno));
		return NULL;
	}
	private = key_load_private_type(KEY_UNSPEC, filename, "", NULL, &perm_ok);
	if (!perm_ok) {
		if (private != NULL)
			key_free(private);
		return NULL;
	}
	if (private == NULL) {
		if (options.batch_mode)
			return NULL;
		snprintf(prompt, sizeof prompt,
		    "Enter passphrase for key '%.100s': ", filename);
		for (i = 0; i < options.number_of_password_prompts; i++) {
			passphrase = read_passphrase(prompt, 0);
			if (strcmp(passphrase, "") != 0) {
				private = key_load_private_type(KEY_UNSPEC,
				    filename, passphrase, NULL, NULL);
				quit = 0;
			} else {
				debug2("no passphrase given, try next key");
				quit = 1;
			}
			explicit_bzero(passphrase, strlen(passphrase));
			free(passphrase);
			if (private != NULL || quit)
				break;
			debug2("bad passphrase given, try again...");
		}
	}
	return private;
}

/*
 * try keys in the following order:
 *	1. agent keys that are found in the config file
 *	2. other agent keys
 *	3. keys that are only listed in the config file
 */
static void
pubkey_prepare(Authctxt *authctxt)
{
	Identity *id, *id2, *tmp;
	Idlist agent, files, *preferred;
	Key *key;
	AuthenticationConnection *ac;
	char *comment;
	int i, found;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	preferred = &authctxt->keys;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	for (i = 0; i < options.num_identity_files; i++) {
		key = options.identity_keys[i];
		if (key && key->type == KEY_RSA1)
			continue;
		if (key && key->cert && key->cert->type != SSH2_CERT_TYPE_USER)
			continue;
		options.identity_keys[i] = NULL;
		id = xcalloc(1, sizeof(*id));
		id->key = key;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, next);
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, next, tmp) {
		if (id->key == NULL || (id->key->flags & SSHKEY_FLAG_EXT) == 0)
			continue;
		found = 0;
		TAILQ_FOREACH(id2, &files, next) {
			if (id2->key == NULL ||
			    (id2->key->flags & SSHKEY_FLAG_EXT) == 0)
				continue;
			if (key_equal(id->key, id2->key)) {
				TAILQ_REMOVE(&files, id, next);
				TAILQ_INSERT_TAIL(preferred, id, next);
				found = 1;
				break;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		if (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, next);
			explicit_bzero(id, sizeof(*id));
			free(id);
		}
	}
	/* list of keys supported by the agent */
	if ((ac = ssh_get_authentication_connection())) {
		for (key = ssh_get_first_identity(ac, &comment, 2);
		    key != NULL;
		    key = ssh_get_next_identity(ac, &comment, 2)) {
			found = 0;
			TAILQ_FOREACH(id, &files, next) {
				/* agent keys from the config file are preferred */
				if (key_equal(key, id->key)) {
					key_free(key);
					free(comment);
					TAILQ_REMOVE(&files, id, next);
					TAILQ_INSERT_TAIL(preferred, id, next);
					id->ac = ac;
					found = 1;
					break;
				}
			}
			if (!found && !options.identities_only) {
				id = xcalloc(1, sizeof(*id));
				id->key = key;
				id->filename = comment;
				id->ac = ac;
				TAILQ_INSERT_TAIL(&agent, id, next);
			}
		}
		/* append remaining agent keys */
		for (id = TAILQ_FIRST(&agent); id; id = TAILQ_FIRST(&agent)) {
			TAILQ_REMOVE(&agent, id, next);
			TAILQ_INSERT_TAIL(preferred, id, next);
		}
		authctxt->agent = ac;
	}
	/* append remaining keys from the config file */
	for (id = TAILQ_FIRST(&files); id; id = TAILQ_FIRST(&files)) {
		TAILQ_REMOVE(&files, id, next);
		TAILQ_INSERT_TAIL(preferred, id, next);
	}
	TAILQ_FOREACH(id, preferred, next) {
		debug2("key: %s (%p),%s", id->filename, id->key,
		    id->userprovided ? " explicit" : "");
	}
}

static void
pubkey_cleanup(Authctxt *authctxt)
{
	Identity *id;

	if (authctxt->agent != NULL)
		ssh_close_authentication_connection(authctxt->agent);
	for (id = TAILQ_FIRST(&authctxt->keys); id;
	    id = TAILQ_FIRST(&authctxt->keys)) {
		TAILQ_REMOVE(&authctxt->keys, id, next);
		if (id->key)
			key_free(id->key);
		free(id->filename);
		free(id);
	}
}

int
userauth_pubkey(Authctxt *authctxt)
{
	Identity *id;
	int sent = 0;

	while ((id = TAILQ_FIRST(&authctxt->keys))) {
		if (id->tried++)
			return (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->keys, id, next);
		TAILQ_INSERT_TAIL(&authctxt->keys, id, next);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		if (id->key != NULL) {
			if (key_type_plain(id->key->type) == KEY_RSA &&
			    (datafellows & SSH_BUG_RSASIGMD5) != 0) {
				debug("Skipped %s key %s for RSA/MD5 server",
				    key_type(id->key), id->filename);
			} else if (id->key->type != KEY_RSA1) {
				debug("Offering %s public key: %s",
				    key_type(id->key), id->filename);
				sent = send_pubkey_test(authctxt, id);
			}
		} else {
			debug("Trying private key: %s", id->filename);
			id->key = load_identity_file(id->filename,
			    id->userprovided);
			if (id->key != NULL) {
				id->isprivate = 1;
				if (key_type_plain(id->key->type) == KEY_RSA &&
				    (datafellows & SSH_BUG_RSASIGMD5) != 0) {
					debug("Skipped %s key %s for RSA/MD5 "
					    "server", key_type(id->key),
					    id->filename);
				} else {
					sent = sign_and_send_pubkey(
					    authctxt, id);
				}
				key_free(id->key);
				id->key = NULL;
			}
		}
		if (sent)
			return (sent);
	}
	return (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
int
userauth_kbdint(Authctxt *authctxt)
{
	static int attempt = 0;

	if (attempt++ >= options.number_of_password_prompts)
		return 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	if (attempt > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		dispatch_set(SSH2_MSG_USERAUTH_INFO_REQUEST, NULL);
		return 0;
	}

	debug2("userauth_kbdint");
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_put_cstring("");					/* lang */
	packet_put_cstring(options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "");
	packet_send();

	dispatch_set(SSH2_MSG_USERAUTH_INFO_REQUEST, &input_userauth_info_req);
	return 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
void
input_userauth_info_req(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	char *name, *inst, *lang, *prompt, *response;
	u_int num_prompts, i;
	int echo = 0;

	debug2("input_userauth_info_req");

	if (authctxt == NULL)
		fatal("input_userauth_info_req: no authentication context");

	authctxt->info_req_seen = 1;

	name = packet_get_string(NULL);
	inst = packet_get_string(NULL);
	lang = packet_get_string(NULL);
	if (strlen(name) > 0)
		logit("%s", name);
	if (strlen(inst) > 0)
		logit("%s", inst);
	free(name);
	free(inst);
	free(lang);

	num_prompts = packet_get_int();
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	packet_start(SSH2_MSG_USERAUTH_INFO_RESPONSE);
	packet_put_int(num_prompts);

	debug2("input_userauth_info_req: num_prompts %d", num_prompts);
	for (i = 0; i < num_prompts; i++) {
		prompt = packet_get_string(NULL);
		echo = packet_get_char();

		response = read_passphrase(prompt, echo ? RP_ECHO : 0);

		packet_put_cstring(response);
		explicit_bzero(response, strlen(response));
		free(response);
		free(prompt);
	}
	packet_check_eom(); /* done with parsing incoming message. */

	packet_add_padding(64);
	packet_send();
}

static int
ssh_keysign(Key *key, u_char **sigp, u_int *lenp,
    u_char *data, u_int datalen)
{
	Buffer b;
	struct stat st;
	pid_t pid;
	int to[2], from[2], status, version = 2;

	debug2("ssh_keysign called");

	if (stat(_PATH_SSH_KEY_SIGN, &st) < 0) {
		error("ssh_keysign: not installed: %s", strerror(errno));
		return -1;
	}
	if (fflush(stdout) != 0)
		error("ssh_keysign: fflush: %s", strerror(errno));
	if (pipe(to) < 0) {
		error("ssh_keysign: pipe: %s", strerror(errno));
		return -1;
	}
	if (pipe(from) < 0) {
		error("ssh_keysign: pipe: %s", strerror(errno));
		return -1;
	}
	if ((pid = fork()) < 0) {
		error("ssh_keysign: fork: %s", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		/* keep the socket on exec */
		fcntl(packet_get_connection_in(), F_SETFD, 0);
		permanently_drop_suid(getuid());
		close(from[0]);
		if (dup2(from[1], STDOUT_FILENO) < 0)
			fatal("ssh_keysign: dup2: %s", strerror(errno));
		close(to[1]);
		if (dup2(to[0], STDIN_FILENO) < 0)
			fatal("ssh_keysign: dup2: %s", strerror(errno));
		close(from[1]);
		close(to[0]);
		execl(_PATH_SSH_KEY_SIGN, _PATH_SSH_KEY_SIGN, (char *) 0);
		fatal("ssh_keysign: exec(%s): %s", _PATH_SSH_KEY_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);

	buffer_init(&b);
	buffer_put_int(&b, packet_get_connection_in()); /* send # of socket */
	buffer_put_string(&b, data, datalen);
	if (ssh_msg_send(to[1], version, &b) == -1)
		fatal("ssh_keysign: couldn't send request");

	if (ssh_msg_recv(from[0], &b) < 0) {
		error("ssh_keysign: no reply");
		buffer_free(&b);
		return -1;
	}
	close(from[0]);
	close(to[1]);

	while (waitpid(pid, &status, 0) < 0)
		if (errno != EINTR)
			break;

	if (buffer_get_char(&b) != version) {
		error("ssh_keysign: bad version");
		buffer_free(&b);
		return -1;
	}
	*sigp = buffer_get_string(&b, lenp);
	buffer_free(&b);

	return 0;
}

int
userauth_hostbased(Authctxt *authctxt)
{
	Key *private = NULL;
	Sensitive *sensitive = authctxt->sensitive;
	Buffer b;
	u_char *signature, *blob;
	char *chost, *pkalg, *p;
	const char *service;
	u_int blen, slen;
	int ok, i, found = 0;

	/* check for a useful key */
	for (i = 0; i < sensitive->nkeys; i++) {
		private = sensitive->keys[i];
		if (private && private->type != KEY_RSA1) {
			found = 1;
			/* we take and free the key */
			sensitive->keys[i] = NULL;
			break;
		}
	}
	if (!found) {
		debug("No more client hostkeys for hostbased authentication.");
		return 0;
	}
	if (key_to_blob(private, &blob, &blen) == 0) {
		key_free(private);
		return 0;
	}
	/* figure out a name for the client host */
	p = get_local_name(packet_get_connection_in());
	if (p == NULL) {
		error("userauth_hostbased: cannot get local ipaddr/name");
		key_free(private);
		free(blob);
		return 0;
	}
	xasprintf(&chost, "%s.", p);
	debug2("userauth_hostbased: chost %s", chost);
	free(p);

	service = datafellows & SSH_BUG_HBSERVICE ? "ssh-userauth" :
	    authctxt->service;
	pkalg = xstrdup(key_ssh_name(private));
	buffer_init(&b);
	/* construct data */
	buffer_put_string(&b, session_id2, session_id2_len);
	buffer_put_char(&b, SSH2_MSG_USERAUTH_REQUEST);
	buffer_put_cstring(&b, authctxt->server_user);
	buffer_put_cstring(&b, service);
	buffer_put_cstring(&b, authctxt->method->name);
	buffer_put_cstring(&b, pkalg);
	buffer_put_string(&b, blob, blen);
	buffer_put_cstring(&b, chost);
	buffer_put_cstring(&b, authctxt->local_user);
#ifdef DEBUG_PK
	buffer_dump(&b);
#endif
	if (sensitive->external_keysign)
		ok = ssh_keysign(private, &signature, &slen,
		    buffer_ptr(&b), buffer_len(&b));
	else
		ok = key_sign(private, &signature, &slen,
		    buffer_ptr(&b), buffer_len(&b));
	key_free(private);
	buffer_free(&b);
	if (ok != 0) {
		error("key_sign failed");
		free(chost);
		free(pkalg);
		free(blob);
		return 0;
	}
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_put_cstring(pkalg);
	packet_put_string(blob, blen);
	packet_put_cstring(chost);
	packet_put_cstring(authctxt->local_user);
	packet_put_string(signature, slen);
	explicit_bzero(signature, slen);
	free(signature);
	free(chost);
	free(pkalg);
	free(blob);

	packet_send();
	return 1;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
static int
authmethod_is_enabled(Authmethod *method)
{
	if (method == NULL)
		return 0;
	/* return false if options indicate this method is disabled */
	if  (method->enabled == NULL || *method->enabled == 0)
		return 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	if  (method->batch_flag != NULL && *method->batch_flag != 0)
		return 0;
	return 1;
}

static Authmethod *
authmethod_lookup(const char *name)
{
	Authmethod *method = NULL;
	if (name != NULL)
		for (method = authmethods; method->name != NULL; method++)
			if (strcmp(name, method->name) == 0)
				return method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	return NULL;
}

/* XXX internal state */
static Authmethod *current = NULL;
static char *supported = NULL;
static char *preferred = NULL;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
static Authmethod *
authmethod_get(char *authlist)
{
	char *name = NULL;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	if (authlist == NULL || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	if (supported == NULL || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		free(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = NULL;
	} else if (current != NULL && authmethod_is_enabled(current))
		return current;

	for (;;) {
		if ((name = match_list(preferred, supported, &next)) == NULL) {
			debug("No more authentication methods to try.");
			current = NULL;
			return NULL;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		if ((current = authmethod_lookup(name)) != NULL &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			free(name);
			return current;
		}
		free(name);
	}
}

static char *
authmethods_get(void)
{
	Authmethod *method = NULL;
	Buffer b;
	char *list;

	buffer_init(&b);
	for (method = authmethods; method->name != NULL; method++) {
		if (authmethod_is_enabled(method)) {
			if (buffer_len(&b) > 0)
				buffer_append(&b, ",", 1);
			buffer_append(&b, method->name, strlen(method->name));
		}
	}
	buffer_append(&b, "\0", 1);
	list = xstrdup(buffer_ptr(&b));
	buffer_free(&b);
	return list;
}

