/*
 * Copyright 2001 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
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
RCSID("$OpenBSD$");

#include <openssl/dh.h>

#include "ssh.h"
#include "auth.h"
#include "kex.h"
#include "dh.h"
#include "zlib.h"
#include "packet.h"
#include "auth-options.h"
#include "sshpty.h"
#include "channels.h"
#include "session.h"
#include "log.h"
#include "monitor.h"
#include "monitor_mm.h"
#include "monitor_wrap.h"
#include "monitor_fdpass.h"
#include "xmalloc.h"
#include "misc.h"
#include "buffer.h"
#include "bufaux.h"

/* Imports */
extern Newkeys *current_keys[];
extern z_stream incoming_stream;
extern z_stream outgoing_stream;
extern int compat20;
extern int mm_sendfd;

/* State exported from the child */

struct {
	z_stream incoming;
	z_stream outgoing;
	u_char *keyin;
	u_int keyinlen;
	u_char *keyout;
	u_int keyoutlen;
} child_state;

/* Prototype for authentication functions */

int hostbased_key_allowed(struct passwd *, const char *, char *, Key *);
int user_key_allowed(struct passwd *, Key *);
Key *get_hostkey_by_index(int);

void	session_pty_cleanup(void *);

static Authctxt *authctxt;

struct mon_table {
	enum monitor_reqtype type;
	int flags;
	int (*f)(int, Buffer *);
};

#define MON_PROTOONE	0x0001	/* Used in protocol 1 */
#define MON_PROTOTWO	0x0002	/* Used in protocol 2 */
#define MON_AUTH	0x0004	/* Authentication Request */

#define MON_BOTH	(MON_PROTOONE|MON_PROTOTWO)

#define MON_PERMIT	0x1000	/* Request is permitted */

struct mon_table mon_dispatch_proto20[] = {
    {MONITOR_REQ_MODULI, MON_PROTOTWO, mm_answer_moduli},
    {MONITOR_REQ_SIGN, MON_PROTOTWO, mm_answer_sign},
    {MONITOR_REQ_PWNAM, MON_BOTH, mm_answer_pwnamallow},
    {MONITOR_REQ_AUTHSERV, MON_BOTH, mm_answer_authserv},
    {MONITOR_REQ_AUTHPASSWORD, MON_BOTH | MON_AUTH, mm_answer_authpassword},
    {MONITOR_REQ_KEYALLOWED, MON_BOTH | MON_AUTH, mm_answer_keyallowed},
    {MONITOR_REQ_KEYVERIFY, MON_BOTH | MON_AUTH, mm_answer_keyverify},
    {0, 0, NULL}
};

struct mon_table mon_dispatch_postauth20[] = {
    {MONITOR_REQ_MODULI, MON_PROTOTWO, mm_answer_moduli},
    {MONITOR_REQ_SIGN, MON_PROTOTWO, mm_answer_sign},
    {MONITOR_REQ_PTY, MON_BOTH, mm_answer_pty},
    {MONITOR_REQ_TERM, MON_BOTH, mm_answer_term},
    {0, 0, NULL}
};

struct mon_table mon_dispatch_proto15[] = {
    {0, 0, NULL}
};

struct mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */

void
monitor_permit(struct mon_table *ent, enum monitor_reqtype type, int permit)
{
	while (ent->f != NULL) {
		if (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			return;
		}
		ent++;
	}
}

void
monitor_permit_authentications(int permit)
{
	struct mon_table *ent = mon_dispatch;

	while (ent->f != NULL) {
		if (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

#define FD_CLOSEONEXEC(x) do { \
	if (fcntl(x, F_SETFD, 1) == -1) \
		fatal("fcntl(%d, F_SETFD)", x); \
} while (0)

void
monitor_socketpair(int *pair)
{
	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) == -1)
		fatal("%s: socketpair", __FUNCTION__);
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
}

Authctxt *
monitor_child_preauth(int socket)
{
	debug3("preauth child monitor started");

	if (compat20) {
		mon_dispatch = mon_dispatch_proto20;

		/* Permit requests for moduli and signatures */
		monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	} else
		mon_dispatch = mon_dispatch_proto15;

	authctxt = authctxt_new();

	/* The first few requests do not require asynchronous access */
	for (;;) {
		if (monitor_read(socket, mon_dispatch))
			break;
	}

	debug("%s: %s has been authenticated by privileged process",
	    __FUNCTION__, authctxt->user);

	if (compat20) {
		mm_get_keystate(socket);
	} else {
		fatal("Use loose");
	}

	return (authctxt);
}

void
monitor_child_postauth(int socket)
{
	if (compat20) {
		mon_dispatch = mon_dispatch_postauth20;

		/* Permit requests for moduli and signatures */
		monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_TERM, 1);

		if (!no_pty_flag)
			monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
	} else
		mon_dispatch = mon_dispatch_proto15;

	for (;;) {
		if (monitor_read(socket, mon_dispatch))
			break;
	}
}

int
monitor_read(int socket, struct mon_table *ent)
{
	Buffer m;
	int ret;
	u_char type;

	buffer_init(&m);

	mm_request_receive(socket, &m);
	type = buffer_get_char(&m);

	debug3("%s: checking request %d", __FUNCTION__, type);

	while (ent->f != NULL) {
		if (ent->type == type)
			break;
		ent++;
	}

	if (ent->f != NULL) {
		if (!(ent->flags & MON_PERMIT))
			fatal("%s: unpermitted request %d", __FUNCTION__,
			    type);
		ret = (*ent->f)(socket, &m);
		buffer_free(&m);
		return ret;
	}

	fatal("%s: unsupported request: %d\n", __FUNCTION__, type); 

	/* NOTREACHED */
	return (-1);
}

int
mm_answer_moduli(int socket, Buffer *m)
{
	DH *dh;
	int min, want, max;

	/* Turn off requests for moduli */
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 0);

	min = buffer_get_int(m);
	want = buffer_get_int(m);
	max = buffer_get_int(m);

	debug3("%s: got parameters: %d %d %d",
	    __FUNCTION__, min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	if (max < min || want < min || max < want)
		fatal("%s: bad parameters: %d %d %d",
		    __FUNCTION__, min, want, max);

	buffer_clear(m);

	dh = choose_dh(min, want, max);
	if (dh == NULL) {
		buffer_put_char(m, 0);
		return (0);
	} else {
		/* Send first bignum */
		buffer_put_char(m, 1);
		buffer_put_bignum2(m, dh->p);
		buffer_put_bignum2(m, dh->g);
		
		DH_free(dh);
	}
	mm_request_send(socket, MONITOR_ANS_MODULI, m);
	return (0);
}

int
mm_answer_sign(int socket, Buffer *m)
{
	Key *key;
	u_char *p;
	u_char *signature;
	u_int siglen, datlen;
	int keyid;
	
	debug3("%s", __FUNCTION__);

	keyid = buffer_get_int(m);	
	p = buffer_get_string(m, &datlen);	

	if ((key = get_hostkey_by_index(keyid)) == NULL)
		fatal("%s: no hostkey from index %d", __FUNCTION__, keyid);
	if (key_sign(key, &signature, &siglen, p, datlen) < 0)
		fatal("%s: key_sign failed", __FUNCTION__);

	debug3("%s: signature %p(%d)", __FUNCTION__, signature, siglen);

	buffer_clear(m);
	buffer_put_string(m, signature, siglen);

	xfree(p);
	xfree(signature);
	
	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	mm_request_send(socket, MONITOR_ANS_SIGN, m);
	return (0);
}

/* Retrieves the password entry and also checks if the user is permitted */

int
mm_answer_pwnamallow(int socket, Buffer *m)
{
	char *login;
	struct passwd *pwent;
	int allowed;
	
	debug3("%s", __FUNCTION__);

	if (authctxt->attempt++ != 0)
		fatal("%s: multiple attempts for getpwnam", __FUNCTION__);

	login = buffer_get_string(m, NULL);

	/* XXX - probably latch the username here */
	pwent = getpwnam(login);
	authctxt->user = xstrdup(login);
	setproctitle("%s [priv]", pwent ? login : "unknown");
	xfree(login);

	/* Allow service/style information on the auth context */
	monitor_permit(mon_dispatch, MONITOR_REQ_AUTHSERV, 1);

	buffer_clear(m);

	if (pwent == NULL) {
		buffer_put_char(m, 0);
		mm_request_send(socket, MONITOR_ANS_PWNAM, m);
		return (0);
	}

	/* Check if we permit this user */
	allowed = allowed_user(pwent);

	if (allowed) {
		authctxt->pw = pwcopy(pwent);
		authctxt->valid = 1;
	}
	buffer_put_char(m, allowed);
	buffer_put_string(m, pwent, sizeof(struct passwd));
	buffer_put_cstring(m, pwent->pw_name);
	buffer_put_cstring(m, "*");
	buffer_put_cstring(m, pwent->pw_gecos);
	buffer_put_cstring(m, pwent->pw_class);
	buffer_put_cstring(m, pwent->pw_dir);
	buffer_put_cstring(m, pwent->pw_shell);

	debug3("%s: sending MONITOR_ANS_PWNAM: %d", __FUNCTION__, allowed);
	mm_request_send(socket, MONITOR_ANS_PWNAM, m);

	return (0);
}

int
mm_answer_authserv(int socket, Buffer *m)
{
	/* Disallow service/style information on the auth context */
	monitor_permit(mon_dispatch, MONITOR_REQ_AUTHSERV, 0);

	monitor_permit_authentications(1);

	authctxt->service = buffer_get_string(m, NULL);
	authctxt->style = buffer_get_string(m, NULL);
	if (strlen(authctxt->style) == 0) {
		xfree(authctxt->style);
		authctxt->style = NULL;
	}

	debug3("%s: service=%s, style=%s",
	    __FUNCTION__, authctxt->service, authctxt->style);

	return (0);
}

int
mm_answer_authpassword(int socket, Buffer *m)
{
	char *passwd;
	int authenticated;

	passwd = buffer_get_string(m, NULL);
	/* Only authenticate if the context is valid */
	authenticated = authctxt->valid && auth_password(authctxt, passwd);
	memset(passwd, 0, strlen(passwd));
	xfree(passwd);

	buffer_clear(m);
	buffer_put_int(m, authenticated);

	debug3("%s: sending result %d", __FUNCTION__, authenticated);
	mm_request_send(socket, MONITOR_ANS_AUTHPASSWORD, m);

	/* Causes monitor loop to terminate if authenticated */
	return (authenticated);
}

int
mm_answer_keyallowed(int socket, Buffer *m)
{
	Key *key;
	u_char *cuser, *chost, *blob;
	u_int bloblen;
	enum mm_keytype type = 0;
	int allowed = 0;

	debug3("%s entering", __FUNCTION__);
	
	type = buffer_get_int(m);
	cuser = buffer_get_string(m, NULL);
	chost = buffer_get_string(m, NULL);
	blob = buffer_get_string(m, &bloblen);

	key = key_from_blob(blob, bloblen);

	debug3("%s: key_from_blob: %p", __FUNCTION__, key);

	if (key != NULL && authctxt->pw != NULL) {
		switch(type) {
		case MM_USERKEY:
			allowed = user_key_allowed(authctxt->pw, key);
			break;
		case MM_HOSTKEY:
			allowed = hostbased_key_allowed(authctxt->pw,
			    cuser, chost, key);
			break;
		default:
			fatal("%s: unknown key type %d", __FUNCTION__,
			    type);
			break;
		}
		key_free(key);
	}
	xfree(chost);
	xfree(cuser);
	xfree(blob);

	debug3("%s: key %p is %s",
	    __FUNCTION__, key, allowed ? "allowed" : "disallowed");

	buffer_clear(m);
	buffer_put_int(m, allowed);

	mm_request_send(socket, MONITOR_ANS_KEYALLOWED, m);
	return (0);
}

int
mm_answer_keyverify(int socket, Buffer *m)
{
	Key *key;
	u_char *signature, *data, *cuser, *chost, *blob;
	u_int signaturelen, datalen, bloblen;
	int type;
	int verified = 0;

	type = buffer_get_int(m);
	cuser = buffer_get_string(m, NULL);
	chost = buffer_get_string(m, NULL);
	blob = buffer_get_string(m, &bloblen);
	signature = buffer_get_string(m, &signaturelen);
	data = buffer_get_string(m, &datalen);

	key = key_from_blob(blob, bloblen);
	if (key == NULL)
		fatal("%s: bad public key blob", __FUNCTION__);

	if (authctxt->pw == NULL || !user_key_allowed(authctxt->pw, key))
		fatal("%s: user not allowed", __FUNCTION__);
	verified = key_verify(key, signature, signaturelen, data, datalen);
	debug3("%s: key %p signature %s",
	    __FUNCTION__, key, verified ? "verified" : "unverified");

	key_free(key);
	xfree(chost);
	xfree(cuser);
	xfree(blob);
	xfree(signature);
	xfree(data);
		
	buffer_clear(m);
	buffer_put_int(m, verified);
	mm_request_send(socket, MONITOR_ANS_KEYVERIFY, m);

	return (verified);
}

int
mm_answer_pty(int socket, Buffer *m)
{
	Session *s;
	int res;

	debug3("%s entering", __FUNCTION__);

	buffer_clear(m);
	s = session_new();
	if (s == NULL)
		goto error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, sizeof(s->tty));
	if (res == 0)
		goto error;
	fatal_add_cleanup(session_pty_cleanup, (void *)s);
	pty_setowner(authctxt->pw, s->tty);

	buffer_put_int(m, 1);
	buffer_put_cstring(m, s->tty);
	mm_request_send(socket, MONITOR_ANS_PTY, m);

	mm_send_fd(mm_sendfd, s->ptyfd);
	mm_send_fd(mm_sendfd, s->ttyfd);
	return (0);

 error:
	if (s != NULL)
		session_close(s);
	buffer_put_int(m, 0);
	mm_request_send(socket, MONITOR_ANS_PTY, m);
	return (0);
}

int
mm_answer_term(int socket, Buffer *req)
{
	debug3("%s: tearing down sessions", __FUNCTION__);

	/* The child is terminating */
	session_destroy_all();

	return (1);
}

void
mm_apply_keystate(struct mm_master *mm)
{
	/* XXX - delegate to child? */
	set_newkeys(MODE_IN);
	set_newkeys(MODE_OUT);

	packet_set_keycontext(MODE_OUT, child_state.keyout);
	xfree(child_state.keyout);
	packet_set_keycontext(MODE_IN, child_state.keyin);
	xfree(child_state.keyin);

	memcpy(&incoming_stream, &child_state.incoming,
	    sizeof(incoming_stream));
	memcpy(&outgoing_stream, &child_state.outgoing,
	    sizeof(outgoing_stream));
	
	/* Update with new address */
	mm_init_compression(mm);
}

/* This function requries careful sanity checking */

void
mm_get_keystate(int socket)
{
	Buffer m;
	u_char *blob, *p;
	u_int bloblen, plen;

	debug3("%s: Waiting for new keys", __FUNCTION__);

	buffer_init(&m);
	mm_request_receive_expect(socket, MONITOR_REQ_KEYEXPORT, &m);

	blob = buffer_get_string(&m, &bloblen);
	current_keys[MODE_OUT] = mm_newkeys_from_blob(blob, bloblen);
	xfree(blob);

	debug3("%s: Waiting for second key", __FUNCTION__);
	blob = buffer_get_string(&m, &bloblen);
	current_keys[MODE_IN] = mm_newkeys_from_blob(blob, bloblen);
	xfree(blob);
	
	/* Now get sequence numbers for the packets */
	packet_set_seqnr(MODE_OUT, buffer_get_int(&m));
	packet_set_seqnr(MODE_IN, buffer_get_int(&m));

	/* Get the key context */
	child_state.keyout = buffer_get_string(&m, &child_state.keyoutlen);
	child_state.keyin  = buffer_get_string(&m, &child_state.keyinlen);

	debug3("%s: Getting compression state", __FUNCTION__);
	/* Get compression state */
	p = buffer_get_string(&m, &plen);
	if (plen != sizeof(child_state.outgoing))
		fatal("%s: bad request size", __FUNCTION__);
	memcpy(&child_state.outgoing, p, sizeof(child_state.outgoing));
	xfree(p);

	p = buffer_get_string(&m, &plen);
	if (plen != sizeof(child_state.incoming))
		fatal("%s: bad request size", __FUNCTION__);
	memcpy(&child_state.incoming, p, sizeof(child_state.incoming));
	xfree(p);

	buffer_free(&m);
}


/* Allocation functions for zlib */
void *
mm_zalloc(struct mm_master *mm, u_int ncount, u_int size)
{
	void *address;

	address = mm_malloc(mm, size * ncount);

	return (address);
}

void
mm_zfree(struct mm_master *mm, void *address)
{
	mm_free(mm, address);
}

void
mm_init_compression(struct mm_master *mm)
{
	outgoing_stream.zalloc = (alloc_func)mm_zalloc;
	outgoing_stream.zfree = (free_func)mm_zfree;
	outgoing_stream.opaque = mm;

	incoming_stream.zalloc = (alloc_func)mm_zalloc;
	incoming_stream.zfree = (free_func)mm_zfree;
	incoming_stream.opaque = mm;
}
