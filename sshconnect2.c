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
RCSID("$OpenBSD: sshconnect2.c,v 1.57 2001/03/27 17:46:49 provos Exp $");

#include <openssl/bn.h>
#include <openssl/md5.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>

#include "ssh.h"
#include "ssh2.h"
#include "xmalloc.h"
#include "rsa.h"
#include "buffer.h"
#include "packet.h"
#include "uidswap.h"
#include "compat.h"
#include "bufaux.h"
#include "cipher.h"
#include "kex.h"
#include "myproposal.h"
#include "key.h"
#include "sshconnect.h"
#include "authfile.h"
#include "cli.h"
#include "dh.h"
#include "dispatch.h"
#include "authfd.h"
#include "log.h"
#include "readconf.h"
#include "readpass.h"
#include "match.h"

void ssh_dh1_client(Kex *, char *, struct sockaddr *, Buffer *, Buffer *);
void ssh_dhgex_client(Kex *, char *, struct sockaddr *, Buffer *, Buffer *);

/* import */
extern char *client_version_string;
extern char *server_version_string;
extern Options options;

/*
 * SSH2 key exchange
 */

u_char *session_id2 = NULL;
int session_id2_len = 0;

void
ssh_kex2(char *host, struct sockaddr *hostaddr)
{
	int i, plen;
	Kex *kex;
	Buffer *client_kexinit, *server_kexinit;
	char *sprop[PROPOSAL_MAX];

	if (options.ciphers == (char *)-1) {
		log("No valid ciphers for protocol version 2 given, using defaults.");
		options.ciphers = NULL;
	}
	if (options.ciphers != NULL) {
		myproposal[PROPOSAL_ENC_ALGS_CTOS] =
		myproposal[PROPOSAL_ENC_ALGS_STOC] = options.ciphers;
	}
	if (options.compression) {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
		myproposal[PROPOSAL_COMP_ALGS_STOC] = "zlib";
	} else {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
		myproposal[PROPOSAL_COMP_ALGS_STOC] = "none";
	}
	if (options.macs != NULL) {
		myproposal[PROPOSAL_MAC_ALGS_CTOS] =
		myproposal[PROPOSAL_MAC_ALGS_STOC] = options.macs;
	}

	myproposal[PROPOSAL_ENC_ALGS_STOC] =
	    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_STOC]);

	/* buffers with raw kexinit messages */
	server_kexinit = xmalloc(sizeof(*server_kexinit));
	buffer_init(server_kexinit);
	client_kexinit = kex_init(myproposal);

	/* algorithm negotiation */
	kex_exchange_kexinit(client_kexinit, server_kexinit, sprop);
	kex = kex_choose_conf(myproposal, sprop, 0);
	for (i = 0; i < PROPOSAL_MAX; i++)
		xfree(sprop[i]);

	/* server authentication and session key agreement */
	switch(kex->kex_type) {
	case DH_GRP1_SHA1:
		ssh_dh1_client(kex, host, hostaddr,
			       client_kexinit, server_kexinit);
		break;
	case DH_GEX_SHA1:
		ssh_dhgex_client(kex, host, hostaddr, client_kexinit,
				 server_kexinit);
		break;
	default:
		fatal("Unsupported key exchange %d", kex->kex_type);
	}

	buffer_free(client_kexinit);
	buffer_free(server_kexinit);
	xfree(client_kexinit);
	xfree(server_kexinit);

	debug("Wait SSH2_MSG_NEWKEYS.");
	packet_read_expect(&plen, SSH2_MSG_NEWKEYS);
	packet_done();
	debug("GOT SSH2_MSG_NEWKEYS.");

	debug("send SSH2_MSG_NEWKEYS.");
	packet_start(SSH2_MSG_NEWKEYS);
	packet_send();
	packet_write_wait();
	debug("done: send SSH2_MSG_NEWKEYS.");

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	packet_start(SSH2_MSG_IGNORE);
	packet_put_cstring("markus");
	packet_send();
	packet_write_wait();
#endif
	debug("done: KEX2.");
}

/* diffie-hellman-group1-sha1 */

void
ssh_dh1_client(Kex *kex, char *host, struct sockaddr *hostaddr,
	       Buffer *client_kexinit, Buffer *server_kexinit)
{
#ifdef DEBUG_KEXDH
	int i;
#endif
	int plen, dlen;
	u_int klen, kout;
	char *signature = NULL;
	u_int slen;
	char *server_host_key_blob = NULL;
	Key *server_host_key;
	u_int sbloblen;
	DH *dh;
	BIGNUM *dh_server_pub = 0;
	BIGNUM *shared_secret = 0;
	u_char *kbuf;
	u_char *hash;

	debug("Sending SSH2_MSG_KEXDH_INIT.");
	/* generate and send 'e', client DH public key */
	dh = dh_new_group1();
	dh_gen_key(dh, kex->we_need * 8);
	packet_start(SSH2_MSG_KEXDH_INIT);
	packet_put_bignum2(dh->pub_key);
	packet_send();
	packet_write_wait();

#ifdef DEBUG_KEXDH
	fprintf(stderr, "\np= ");
	BN_print_fp(stderr, dh->p);
	fprintf(stderr, "\ng= ");
	BN_print_fp(stderr, dh->g);
	fprintf(stderr, "\npub= ");
	BN_print_fp(stderr, dh->pub_key);
	fprintf(stderr, "\n");
	DHparams_print_fp(stderr, dh);
#endif

	debug("Wait SSH2_MSG_KEXDH_REPLY.");

	packet_read_expect(&plen, SSH2_MSG_KEXDH_REPLY);

	debug("Got SSH2_MSG_KEXDH_REPLY.");

	/* key, cert */
	server_host_key_blob = packet_get_string(&sbloblen);
	server_host_key = key_from_blob(server_host_key_blob, sbloblen);
	if (server_host_key == NULL)
		fatal("cannot decode server_host_key_blob");

	check_host_key(host, hostaddr, server_host_key,
		       options.user_hostfile2, options.system_hostfile2);

	/* DH paramter f, server public DH key */
	dh_server_pub = BN_new();
	if (dh_server_pub == NULL)
		fatal("dh_server_pub == NULL");
	packet_get_bignum2(dh_server_pub, &dlen);

#ifdef DEBUG_KEXDH
	fprintf(stderr, "\ndh_server_pub= ");
	BN_print_fp(stderr, dh_server_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_num_bits(dh_server_pub));
#endif

	/* signed H */
	signature = packet_get_string(&slen);
	packet_done();

	if (!dh_pub_is_valid(dh, dh_server_pub))
		packet_disconnect("bad server public DH value");

	klen = DH_size(dh);
	kbuf = xmalloc(klen);
	kout = DH_compute_key(kbuf, dh_server_pub, dh);
#ifdef DEBUG_KEXDH
	debug("shared secret: len %d/%d", klen, kout);
	fprintf(stderr, "shared secret == ");
	for (i = 0; i< kout; i++)
		fprintf(stderr, "%02x", (kbuf[i])&0xff);
	fprintf(stderr, "\n");
#endif
	shared_secret = BN_new();

	BN_bin2bn(kbuf, kout, shared_secret);
	memset(kbuf, 0, klen);
	xfree(kbuf);

	/* calc and verify H */
	hash = kex_hash(
	    client_version_string,
	    server_version_string,
	    buffer_ptr(client_kexinit), buffer_len(client_kexinit),
	    buffer_ptr(server_kexinit), buffer_len(server_kexinit),
	    server_host_key_blob, sbloblen,
	    dh->pub_key,
	    dh_server_pub,
	    shared_secret
	);
	xfree(server_host_key_blob);
	DH_free(dh);
	BN_free(dh_server_pub);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "hash == ");
	for (i = 0; i< 20; i++)
		fprintf(stderr, "%02x", (hash[i])&0xff);
	fprintf(stderr, "\n");
#endif
	if (key_verify(server_host_key, (u_char *)signature, slen, hash, 20) != 1)
		fatal("key_verify failed for server_host_key");
	key_free(server_host_key);
	xfree(signature);

	kex_derive_keys(kex, hash, shared_secret);
	BN_clear_free(shared_secret);
	packet_set_kex(kex);

	/* save session id */
	session_id2_len = 20;
	session_id2 = xmalloc(session_id2_len);
	memcpy(session_id2, hash, session_id2_len);
}

/* diffie-hellman-group-exchange-sha1 */

/*
 * Estimates the group order for a Diffie-Hellman group that has an
 * attack complexity approximately the same as O(2**bits).  Estimate
 * with:  O(exp(1.9223 * (ln q)^(1/3) (ln ln q)^(2/3)))
 */

int
dh_estimate(int bits)
{

	if (bits < 64)
		return (512);	/* O(2**63) */
	if (bits < 128)
		return (1024);	/* O(2**86) */
	if (bits < 192)
		return (2048);	/* O(2**116) */
	return (4096);		/* O(2**156) */
}

void
ssh_dhgex_client(Kex *kex, char *host, struct sockaddr *hostaddr,
		 Buffer *client_kexinit, Buffer *server_kexinit)
{
#ifdef DEBUG_KEXDH
	int i;
#endif
	int plen, dlen;
	u_int klen, kout;
	char *signature = NULL;
	u_int slen, nbits, min, max;
	char *server_host_key_blob = NULL;
	Key *server_host_key;
	u_int sbloblen;
	DH *dh;
	BIGNUM *dh_server_pub = 0;
	BIGNUM *shared_secret = 0;
	BIGNUM *p = 0, *g = 0;
	u_char *kbuf;
	u_char *hash;

	nbits = dh_estimate(kex->we_need * 8);

	if (datafellows & SSH_OLD_DHGEX) {
		debug("Sending SSH2_MSG_KEX_DH_GEX_REQUEST_OLD.");

		/* Old GEX request */
		packet_start(SSH2_MSG_KEX_DH_GEX_REQUEST_OLD);
		packet_put_int(nbits);
		min = DH_GRP_MIN;
		max = DH_GRP_MAX;
	} else {
		debug("Sending SSH2_MSG_KEX_DH_GEX_REQUEST.");

		/* New GEX request */
		min = DH_GRP_MIN;
		max = MIN(DH_GRP_MAX, nbits * 1.25);

		packet_start(SSH2_MSG_KEX_DH_GEX_REQUEST);
		packet_put_int(min);
		packet_put_int(nbits);
		packet_put_int(max);
	}
	packet_send();
	packet_write_wait();

#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d", min, nbits, max);
#endif

	debug("Wait SSH2_MSG_KEX_DH_GEX_GROUP.");

	packet_read_expect(&plen, SSH2_MSG_KEX_DH_GEX_GROUP);

	debug("Got SSH2_MSG_KEX_DH_GEX_GROUP.");

	if ((p = BN_new()) == NULL)
		fatal("BN_new");
	packet_get_bignum2(p, &dlen);
	if ((g = BN_new()) == NULL)
		fatal("BN_new");
	packet_get_bignum2(g, &dlen);

	if (BN_num_bits(p) < min || BN_num_bits(p) > max)
		fatal("DH_GEX group out of range: %d !< %d !< %d",
		    min, BN_num_bits(p), max);

	dh = dh_new_group(g, p);

	dh_gen_key(dh, kex->we_need * 8);

#ifdef DEBUG_KEXDH
	fprintf(stderr, "\np= ");
	BN_print_fp(stderr, dh->p);
	fprintf(stderr, "\ng= ");
	BN_print_fp(stderr, dh->g);
	fprintf(stderr, "\npub= ");
	BN_print_fp(stderr, dh->pub_key);
	fprintf(stderr, "\n");
	DHparams_print_fp(stderr, dh);
#endif

	debug("Sending SSH2_MSG_KEX_DH_GEX_INIT.");
	/* generate and send 'e', client DH public key */
	packet_start(SSH2_MSG_KEX_DH_GEX_INIT);
	packet_put_bignum2(dh->pub_key);
	packet_send();
	packet_write_wait();

	debug("Wait SSH2_MSG_KEX_DH_GEX_REPLY.");

	packet_read_expect(&plen, SSH2_MSG_KEX_DH_GEX_REPLY);

	debug("Got SSH2_MSG_KEXDH_REPLY.");

	/* key, cert */
	server_host_key_blob = packet_get_string(&sbloblen);
	server_host_key = key_from_blob(server_host_key_blob, sbloblen);
	if (server_host_key == NULL)
		fatal("cannot decode server_host_key_blob");

	check_host_key(host, hostaddr, server_host_key,
		       options.user_hostfile2, options.system_hostfile2);

	/* DH paramter f, server public DH key */
	dh_server_pub = BN_new();
	if (dh_server_pub == NULL)
		fatal("dh_server_pub == NULL");
	packet_get_bignum2(dh_server_pub, &dlen);

#ifdef DEBUG_KEXDH
	fprintf(stderr, "\ndh_server_pub= ");
	BN_print_fp(stderr, dh_server_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_num_bits(dh_server_pub));
#endif

	/* signed H */
	signature = packet_get_string(&slen);
	packet_done();

	if (!dh_pub_is_valid(dh, dh_server_pub))
		packet_disconnect("bad server public DH value");

	klen = DH_size(dh);
	kbuf = xmalloc(klen);
	kout = DH_compute_key(kbuf, dh_server_pub, dh);
#ifdef DEBUG_KEXDH
	debug("shared secret: len %d/%d", klen, kout);
	fprintf(stderr, "shared secret == ");
	for (i = 0; i< kout; i++)
		fprintf(stderr, "%02x", (kbuf[i])&0xff);
	fprintf(stderr, "\n");
#endif
	shared_secret = BN_new();

	BN_bin2bn(kbuf, kout, shared_secret);
	memset(kbuf, 0, klen);
	xfree(kbuf);

	/* calc and verify H */
	hash = kex_hash_gex(
	    client_version_string,
	    server_version_string,
	    buffer_ptr(client_kexinit), buffer_len(client_kexinit),
	    buffer_ptr(server_kexinit), buffer_len(server_kexinit),
	    server_host_key_blob, sbloblen,
	    nbits, dh->p, dh->g,
	    dh->pub_key,
	    dh_server_pub,
	    shared_secret
	);
	xfree(server_host_key_blob);
	DH_free(dh);
	BN_free(dh_server_pub);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "hash == ");
	for (i = 0; i< 20; i++)
		fprintf(stderr, "%02x", (hash[i])&0xff);
	fprintf(stderr, "\n");
#endif
	if (key_verify(server_host_key, (u_char *)signature, slen, hash, 20) != 1)
		fatal("key_verify failed for server_host_key");
	key_free(server_host_key);
	xfree(signature);

	kex_derive_keys(kex, hash, shared_secret);
	BN_clear_free(shared_secret);
	packet_set_kex(kex);

	/* save session id */
	session_id2_len = 20;
	session_id2 = xmalloc(session_id2_len);
	memcpy(session_id2, hash, session_id2_len);
}

/*
 * Authenticate user
 */

typedef struct Authctxt Authctxt;
typedef struct Authmethod Authmethod;

typedef int sign_cb_fn(
    Authctxt *authctxt, Key *key,
    u_char **sigp, int *lenp, u_char *data, int datalen);

struct Authctxt {
	const char *server_user;
	const char *host;
	const char *service;
	AuthenticationConnection *agent;
	Authmethod *method;
	int success;
	char *authlist;
	Key *last_key;
	sign_cb_fn *last_key_sign;
	int last_key_hint;
};
struct Authmethod {
	char	*name;		/* string to compare against server's list */
	int	(*userauth)(Authctxt *authctxt);
	int	*enabled;	/* flag in option struct that enables method */
	int	*batch_flag;	/* flag in option struct that disables method */
};

void	input_userauth_success(int type, int plen, void *ctxt);
void	input_userauth_failure(int type, int plen, void *ctxt);
void	input_userauth_banner(int type, int plen, void *ctxt);
void	input_userauth_error(int type, int plen, void *ctxt);
void	input_userauth_info_req(int type, int plen, void *ctxt);
void	input_userauth_pk_ok(int type, int plen, void *ctxt);

int	userauth_none(Authctxt *authctxt);
int	userauth_pubkey(Authctxt *authctxt);
int	userauth_passwd(Authctxt *authctxt);
int	userauth_kbdint(Authctxt *authctxt);

void	userauth(Authctxt *authctxt, char *authlist);

int
sign_and_send_pubkey(Authctxt *authctxt, Key *k,
    sign_cb_fn *sign_callback);
void	clear_auth_state(Authctxt *authctxt);

Authmethod *authmethod_get(char *authlist);
Authmethod *authmethod_lookup(const char *name);
char *authmethods_get(void);

Authmethod authmethods[] = {
	{"publickey",
		userauth_pubkey,
		&options.pubkey_authentication,
		NULL},
	{"password",
		userauth_passwd,
		&options.password_authentication,
		&options.batch_mode},
	{"keyboard-interactive",
		userauth_kbdint,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		NULL,
		NULL},
	{NULL, NULL, NULL, NULL}
};

void
ssh_userauth2(const char *server_user, char *host)
{
	Authctxt authctxt;
	int type;
	int plen;

	if (options.challenge_reponse_authentication)
		options.kbd_interactive_authentication = 1;

	debug("send SSH2_MSG_SERVICE_REQUEST");
	packet_start(SSH2_MSG_SERVICE_REQUEST);
	packet_put_cstring("ssh-userauth");
	packet_send();
	packet_write_wait();
	type = packet_read(&plen);
	if (type != SSH2_MSG_SERVICE_ACCEPT) {
		fatal("denied SSH2_MSG_SERVICE_ACCEPT: %d", type);
	}
	if (packet_remaining() > 0) {
		char *reply = packet_get_string(&plen);
		debug("service_accept: %s", reply);
		xfree(reply);
	} else {
		debug("buggy server: service_accept w/o service");
	}
	packet_done();
	debug("got SSH2_MSG_SERVICE_ACCEPT");

	if (options.preferred_authentications == NULL)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	authctxt.agent = ssh_get_authentication_connection();
	authctxt.server_user = server_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = NULL;
	if (authctxt.method == NULL)
		fatal("ssh_userauth2: internal error: cannot send userauth none request");

	/* initial userauth request */
	userauth_none(&authctxt);

	dispatch_init(&input_userauth_error);
	dispatch_set(SSH2_MSG_USERAUTH_SUCCESS, &input_userauth_success);
	dispatch_set(SSH2_MSG_USERAUTH_FAILURE, &input_userauth_failure);
	dispatch_set(SSH2_MSG_USERAUTH_BANNER, &input_userauth_banner);
	dispatch_run(DISPATCH_BLOCK, &authctxt.success, &authctxt);	/* loop until success */

	if (authctxt.agent != NULL)
		ssh_close_authentication_connection(authctxt.agent);

	debug("ssh-userauth2 successful: method %s", authctxt.method->name);
}
void
userauth(Authctxt *authctxt, char *authlist)
{
	if (authlist == NULL) {
		authlist = authctxt->authlist;
	} else {
		if (authctxt->authlist)
			xfree(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	for (;;) {
		Authmethod *method = authmethod_get(authlist);
		if (method == NULL)
			fatal("Permission denied (%s).", authlist);
		authctxt->method = method;
		if (method->userauth(authctxt) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			break;
		} else {
			debug2("we did not send a packet, disable method");
			method->enabled = NULL;
		}
	}
}
void
input_userauth_error(int type, int plen, void *ctxt)
{
	fatal("input_userauth_error: bad message during authentication: "
	   "type %d", type);
}
void
input_userauth_banner(int type, int plen, void *ctxt)
{
	char *msg, *lang;
	debug3("input_userauth_banner");
	msg = packet_get_string(NULL);
	lang = packet_get_string(NULL);
	fprintf(stderr, "%s", msg);
	xfree(msg);
	xfree(lang);
}
void
input_userauth_success(int type, int plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	if (authctxt == NULL)
		fatal("input_userauth_success: no authentication context");
	if (authctxt->authlist)
		xfree(authctxt->authlist);
	clear_auth_state(authctxt);
	authctxt->success = 1;			/* break out */
}
void
input_userauth_failure(int type, int plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	char *authlist = NULL;
	int partial;

	if (authctxt == NULL)
		fatal("input_userauth_failure: no authentication context");

	authlist = packet_get_string(NULL);
	partial = packet_get_char();
	packet_done();

	if (partial != 0)
		log("Authenticated with partial success.");
	debug("authentications that can continue: %s", authlist);

	clear_auth_state(authctxt);
	userauth(authctxt, authlist);
}
void
input_userauth_pk_ok(int type, int plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Key *key = NULL;
	Buffer b;
	int alen, blen, pktype, sent = 0;
	char *pkalg, *pkblob, *fp;

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
	packet_done();

	debug("input_userauth_pk_ok: pkalg %s blen %d lastkey %p hint %d",
	    pkalg, blen, authctxt->last_key, authctxt->last_key_hint);

	do {
		if (authctxt->last_key == NULL ||
		    authctxt->last_key_sign == NULL) {
			debug("no last key or no sign cb");
			break;
		}
		if ((pktype = key_type_from_name(pkalg)) == KEY_UNSPEC) {
			debug("unknown pkalg %s", pkalg);
			break;
		}
		if ((key = key_from_blob(pkblob, blen)) == NULL) {
			debug("no key from blob. pkalg %s", pkalg);
			break;
		}
		fp = key_fingerprint(key, SSH_FP_MD5, SSH_FP_HEX);
		debug2("input_userauth_pk_ok: fp %s", fp);
		xfree(fp);
		if (!key_equal(key, authctxt->last_key)) {
			debug("key != last_key");
			break;
		}
		sent = sign_and_send_pubkey(authctxt, key,
		   authctxt->last_key_sign);
	} while(0);

	if (key != NULL)
		key_free(key);
	xfree(pkalg);
	xfree(pkblob);

	/* unregister */
	clear_auth_state(authctxt);
	dispatch_set(SSH2_MSG_USERAUTH_PK_OK, NULL);

	/* try another method if we did not send a packet*/
	if (sent == 0)
		userauth(authctxt, NULL);

}

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
	char prompt[80];
	char *password;

	if (attempt++ >= options.number_of_password_prompts)
		return 0;

	if(attempt != 1)
		error("Permission denied, please try again.");

	snprintf(prompt, sizeof(prompt), "%.30s@%.128s's password: ",
	    authctxt->server_user, authctxt->host);
	password = read_passphrase(prompt, 0);
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_put_char(0);
	packet_put_cstring(password);
	memset(password, 0, strlen(password));
	xfree(password);
	packet_inject_ignore(64);
	packet_send();
	return 1;
}

void
clear_auth_state(Authctxt *authctxt)
{
	/* XXX clear authentication state */
	if (authctxt->last_key != NULL && authctxt->last_key_hint == -1) {
		debug3("clear_auth_state: key_free %p", authctxt->last_key);
		key_free(authctxt->last_key);
	}
	authctxt->last_key = NULL;
	authctxt->last_key_hint = -2;
	authctxt->last_key_sign = NULL;
}

int
sign_and_send_pubkey(Authctxt *authctxt, Key *k, sign_cb_fn *sign_callback)
{
	Buffer b;
	u_char *blob, *signature;
	int bloblen, slen;
	int skip = 0;
	int ret = -1;
	int have_sig = 1;

	debug3("sign_and_send_pubkey");

	if (key_to_blob(k, &blob, &bloblen) == 0) {
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
		buffer_put_cstring(&b, key_ssh_name(k));
	}
	buffer_put_string(&b, blob, bloblen);

	/* generate signature */
	ret = (*sign_callback)(authctxt, k, &signature, &slen,
	    buffer_ptr(&b), buffer_len(&b));
	if (ret == -1) {
		xfree(blob);
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
			buffer_put_cstring(&b, key_ssh_name(k));
		buffer_put_string(&b, blob, bloblen);
	}
	xfree(blob);

	/* append signature */
	buffer_put_string(&b, signature, slen);
	xfree(signature);

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

int
send_pubkey_test(Authctxt *authctxt, Key *k, sign_cb_fn *sign_callback,
    int hint)
{
	u_char *blob;
	int bloblen, have_sig = 0;

	debug3("send_pubkey_test");

	if (key_to_blob(k, &blob, &bloblen) == 0) {
		/* we cannot handle this key */
		debug3("send_pubkey_test: cannot handle key");
		return 0;
	}
	/* register callback for USERAUTH_PK_OK message */
	authctxt->last_key_sign = sign_callback;
	authctxt->last_key_hint = hint;
	authctxt->last_key = k;
	dispatch_set(SSH2_MSG_USERAUTH_PK_OK, &input_userauth_pk_ok);

	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_put_char(have_sig);
	if (!(datafellows & SSH_BUG_PKAUTH))
		packet_put_cstring(key_ssh_name(k));
	packet_put_string(blob, bloblen);
	xfree(blob);
	packet_send();
	return 1;
}

Key *
load_identity_file(char *filename)
{
	Key *private;
	char prompt[300], *passphrase;
	int quit, i;
	struct stat st;

	if (stat(filename, &st) < 0) {
		debug3("no such identity: %s", filename);
		return NULL;
	}
	private = key_load_private_type(KEY_UNSPEC, filename, "", NULL);
	if (private == NULL) {
		if (options.batch_mode)
			return NULL;
		snprintf(prompt, sizeof prompt,
		     "Enter passphrase for key '%.100s': ", filename);
		for (i = 0; i < options.number_of_password_prompts; i++) {
			passphrase = read_passphrase(prompt, 0);
			if (strcmp(passphrase, "") != 0) {
				private = key_load_private_type(KEY_UNSPEC, filename,
				    passphrase, NULL);
				quit = 0;
			} else {
				debug2("no passphrase given, try next key");
				quit = 1;
			}
			memset(passphrase, 0, strlen(passphrase));
			xfree(passphrase);
			if (private != NULL || quit)
				break;
			debug2("bad passphrase given, try again...");
		}
	}
	return private;
}

int
identity_sign_cb(Authctxt *authctxt, Key *key, u_char **sigp, int *lenp,
    u_char *data, int datalen)
{
	Key *private;
	int idx, ret;

	idx = authctxt->last_key_hint;
	if (idx < 0)
		return -1;
	private = load_identity_file(options.identity_files[idx]);
	if (private == NULL)
		return -1;
	ret = key_sign(private, sigp, lenp, data, datalen);
	key_free(private);
	return ret;
}

int agent_sign_cb(Authctxt *authctxt, Key *key, u_char **sigp, int *lenp,
    u_char *data, int datalen)
{
	return ssh_agent_sign(authctxt->agent, key, sigp, lenp, data, datalen);
}

int key_sign_cb(Authctxt *authctxt, Key *key, u_char **sigp, int *lenp,
    u_char *data, int datalen)
{
        return key_sign(key, sigp, lenp, data, datalen);
}

int
userauth_pubkey_agent(Authctxt *authctxt)
{
	static int called = 0;
	int ret = 0;
	char *comment;
	Key *k;

	if (called == 0) {
		if (ssh_get_num_identities(authctxt->agent, 2) == 0)
			debug2("userauth_pubkey_agent: no keys at all");
		called = 1;
	}
	k = ssh_get_next_identity(authctxt->agent, &comment, 2);
	if (k == NULL) {
		debug2("userauth_pubkey_agent: no more keys");
	} else {
		debug("userauth_pubkey_agent: testing agent key %s", comment);
		xfree(comment);
		ret = send_pubkey_test(authctxt, k, agent_sign_cb, -1);
		if (ret == 0)
			key_free(k);
	}
	if (ret == 0)
		debug2("userauth_pubkey_agent: no message sent");
	return ret;
}

int
userauth_pubkey(Authctxt *authctxt)
{
	static int idx = 0;
	int sent = 0;
	Key *key;
	char *filename;

	if (authctxt->agent != NULL) {
		do {
			sent = userauth_pubkey_agent(authctxt);
		} while(!sent && authctxt->agent->howmany > 0);
	}
	while (!sent && idx < options.num_identity_files) {
		key = options.identity_keys[idx];
		filename = options.identity_files[idx];
		if (key == NULL) {
			debug("try privkey: %s", filename);
			key = load_identity_file(filename);
			if (key != NULL) {
				sent = sign_and_send_pubkey(authctxt, key,
				    key_sign_cb);
				key_free(key);
			}
		} else if (key->type != KEY_RSA1) {
			debug("try pubkey: %s", filename);
			sent = send_pubkey_test(authctxt, key,
			    identity_sign_cb, idx);
		}
		idx++;
	}
	return sent;
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
input_userauth_info_req(int type, int plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	char *name, *inst, *lang, *prompt, *response;
	u_int num_prompts, i;
	int echo = 0;

	debug2("input_userauth_info_req");

	if (authctxt == NULL)
		fatal("input_userauth_info_req: no authentication context");

	name = packet_get_string(NULL);
	inst = packet_get_string(NULL);
	lang = packet_get_string(NULL);
	if (strlen(name) > 0)
		cli_mesg(name);
	if (strlen(inst) > 0)
		cli_mesg(inst);
	xfree(name);
	xfree(inst);
	xfree(lang);

	num_prompts = packet_get_int();
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	packet_start(SSH2_MSG_USERAUTH_INFO_RESPONSE);
	packet_put_int(num_prompts);

	for (i = 0; i < num_prompts; i++) {
		prompt = packet_get_string(NULL);
		echo = packet_get_char();

		response = cli_prompt(prompt, echo);

		packet_put_cstring(response);
		memset(response, 0, strlen(response));
		xfree(response);
		xfree(prompt);
	}
	packet_done(); /* done with parsing incoming message. */

	packet_inject_ignore(64);
	packet_send();
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
int
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

Authmethod *
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
Authmethod *
authmethod_get(char *authlist)
{

	char *name = NULL;
	int next;

	/* Use a suitable default if we're passed a nil list.  */
	if (authlist == NULL || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	if (supported == NULL || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		if (supported != NULL)
			xfree(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = NULL;
	} else if (current != NULL && authmethod_is_enabled(current))
		return current;

	for (;;) {
		if ((name = match_list(preferred, supported, &next)) == NULL) {
			debug("no more auth methods to try");
			current = NULL;
			return NULL;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		if ((current = authmethod_lookup(name)) != NULL &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("next auth method to try is %s", name);
			return current;
		}
	}
}


#define	DELIM	","
char *
authmethods_get(void)
{
	Authmethod *method = NULL;
	char buf[1024];

	buf[0] = '\0';
	for (method = authmethods; method->name != NULL; method++) {
		if (authmethod_is_enabled(method)) {
			if (buf[0] != '\0')
				strlcat(buf, DELIM, sizeof buf);
			strlcat(buf, method->name, sizeof buf);
		}
	}
	return xstrdup(buf);
}
