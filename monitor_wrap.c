/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
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

#include <openssl/bn.h>
#include <openssl/dh.h>

#include "ssh.h"
#include "dh.h"
#include "kex.h"
#include "buffer.h"
#include "bufaux.h"
#include "packet.h"
#include "mac.h"
#include "log.h"
#include "zlib.h"
#include "monitor.h"
#include "monitor_wrap.h"
#include "xmalloc.h"
#include "atomicio.h"
#include "monitor_fdpass.h"
#include "getput.h"

/* Imports */
extern Newkeys *newkeys[];
extern z_stream incoming_stream;
extern z_stream outgoing_stream;

void
mm_request_send(int socket, enum monitor_reqtype type, Buffer *m)
{
	u_char buf[5];
	u_int mlen = buffer_len(m);

	debug3("%s entering: type %d", __FUNCTION__, type);

	PUT_32BIT(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	if (atomicio(write, socket, buf, sizeof(buf)) != sizeof(buf))
		fatal("%s: write", __FUNCTION__);
	if (atomicio(write, socket, buffer_ptr(m), mlen) != mlen)
		fatal("%s: write", __FUNCTION__);
}

void
mm_request_receive(int socket, Buffer *m)
{
	u_char buf[4];
	ssize_t res;
	u_int msg_len;

	debug3("%s entering", __FUNCTION__);

	res = atomicio(read, socket, buf, sizeof(buf));
	if (res != sizeof(buf))
		fatal("%s: read: %d", __FUNCTION__, res);
	msg_len = GET_32BIT(buf);
	if (msg_len > 256 * 1024)
		fatal("%s: read: bad msg_len %d", __FUNCTION__, msg_len);
	buffer_clear(m);
	buffer_append_space(m, msg_len);
	res = atomicio(read, socket, buffer_ptr(m), msg_len);
	if (res != msg_len)
		fatal("%s: read: %d != msg_len", __FUNCTION__, res);
}

void
mm_request_receive_expect(int socket, enum monitor_reqtype type, Buffer *m)
{
	u_char rtype;

	debug3("%s entering: type %d", __FUNCTION__, type);

	mm_request_receive(socket, m);
	rtype = buffer_get_char(m);
	if (rtype != type)
		fatal("%s: read: rtype %d != type %d", __FUNCTION__,
		    rtype, type);
}

DH *
mm_choose_dh(int socket, int min, int nbits, int max)
{
	BIGNUM *p, *g;
	int success = 0;
	Buffer m;

	buffer_init(&m);
	buffer_put_int(&m, min);
	buffer_put_int(&m, nbits);
	buffer_put_int(&m, max);

	mm_request_send(socket, MONITOR_REQ_MODULI, &m);

	debug3("%s: waiting for MONITOR_ANS_MODULI", __FUNCTION__);
	mm_request_receive_expect(socket, MONITOR_ANS_MODULI, &m);

	success = buffer_get_char(&m);
	if (success == 0)
		fatal("%s: MONITOR_ANS_MODULI failed", __FUNCTION__);

	if ((p = BN_new()) == NULL)
		fatal("%s: BN_new failed", __FUNCTION__);
	if ((g = BN_new()) == NULL) 
		fatal("%s: BN_new failed", __FUNCTION__);
	buffer_get_bignum2(&m, p);
	buffer_get_bignum2(&m, g);

	debug3("%s: remaining %d", __FUNCTION__, buffer_len(&m));
	buffer_free(&m);

	return (dh_new_group(g, p));
}

int
mm_key_sign(int socket, int keyind, u_char **sigp, u_int *lenp,
    u_char *data, u_int datalen)
{
	Buffer m;

	debug3("%s entering", __FUNCTION__);

	buffer_init(&m);
	buffer_put_int(&m, keyind);
	buffer_put_string(&m, data, datalen);

	mm_request_send(socket, MONITOR_REQ_SIGN, &m);

	debug3("%s: waiting for MONITOR_ANS_SIGN", __FUNCTION__);
	mm_request_receive_expect(socket, MONITOR_ANS_SIGN, &m);
	*sigp  = buffer_get_string(&m, lenp);
	buffer_free(&m);

	return (0);
}

struct passwd *
mm_getpwnamallow(int socket, const char *login, int *allowed)
{
	Buffer m;
	struct passwd *pw;
	u_int pwlen;

	debug3("%s entering", __FUNCTION__);

	buffer_init(&m);
	buffer_put_cstring(&m, login);

	mm_request_send(socket, MONITOR_REQ_PWNAM, &m);

	debug3("%s: waiting for MONITOR_ANS_PWNAM", __FUNCTION__);
	mm_request_receive_expect(socket, MONITOR_ANS_PWNAM, &m);

	*allowed  = buffer_get_char(&m);
	if (*allowed == 0) {
		buffer_free(&m);
		return (NULL);
	}
	pw = buffer_get_string(&m, &pwlen);
	if (pwlen != sizeof(struct passwd))
		fatal("%s: struct passwd size mismatch", __FUNCTION__);
	pw->pw_name = buffer_get_string(&m, NULL);
	pw->pw_passwd = buffer_get_string(&m, NULL);
	pw->pw_gecos = buffer_get_string(&m, NULL);
	pw->pw_class = buffer_get_string(&m, NULL);
	pw->pw_dir = buffer_get_string(&m, NULL);
	pw->pw_shell = buffer_get_string(&m, NULL);
	buffer_free(&m);

	return (pw);
}

void
pwfree(struct passwd *pw)
{
	xfree(pw->pw_name);
	xfree(pw->pw_passwd);
	xfree(pw->pw_gecos);
	xfree(pw->pw_class);
	xfree(pw->pw_dir);
	xfree(pw->pw_shell);
	xfree(pw);
}

/* Inform the privileged process about service and style */

void
mm_inform_authserv(int socket, char *service, char *style)
{
	Buffer m;

	debug3("%s entering", __FUNCTION__);

	buffer_init(&m);
	buffer_put_cstring(&m, service);
	buffer_put_cstring(&m, style ? style : "");

	mm_request_send(socket, MONITOR_REQ_AUTHSERV, &m);

	buffer_free(&m);
}

/* Do the password authentication */
int
mm_auth_password(int socket, char *password)
{
	Buffer m;
	int authenticated = 0;

	debug3("%s entering", __FUNCTION__);

	buffer_init(&m);
	buffer_put_cstring(&m, password);
	mm_request_send(socket, MONITOR_REQ_AUTHPASSWORD, &m);

	debug3("%s: waiting for MONITOR_ANS_AUTHPASSWORD", __FUNCTION__);
	mm_request_receive_expect(socket, MONITOR_ANS_AUTHPASSWORD, &m);

	authenticated = buffer_get_int(&m);

	buffer_free(&m);

	debug3("%s: user %sauthenticated", 
	    __FUNCTION__, authenticated ? "" : "not ");
	return (authenticated);
}

int
mm_key_allowed(int socket, enum mm_keytype type, char *user, char *host,
    Key *key)
{
	Buffer m;
	u_char *blob;
	u_int len;
	int allowed = 0;

	debug3("%s entering", __FUNCTION__);

	/* Convert the key to a blob and the pass it over */
	if (!key_to_blob(key, &blob, &len))
		return (0);

	buffer_init(&m);
	buffer_put_int(&m, type);
	buffer_put_cstring(&m, user ? user : "");
	buffer_put_cstring(&m, host ? host : "");
	buffer_put_string(&m, blob, len);
	xfree(blob);

	mm_request_send(socket, MONITOR_REQ_KEYALLOWED, &m);

	debug3("%s: waiting for MONITOR_ANS_KEYALLOWED", __FUNCTION__);
	mm_request_receive_expect(socket, MONITOR_ANS_KEYALLOWED, &m);

	allowed = buffer_get_int(&m);

	buffer_free(&m);

	return (allowed);
}

/* 
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

int
mm_key_verify(int socket, enum mm_keytype type, char *user, char *host,
    Key *key, u_char *sig, u_int siglen, u_char *data, u_int datalen)
{
	Buffer m;
	u_char *blob;
	u_int len;
	int verified = 0;

	debug3("%s entering", __FUNCTION__);

	/* Convert the key to a blob and the pass it over */
	if (!key_to_blob(key, &blob, &len))
		return (0);

	buffer_init(&m);
	buffer_put_int(&m, type);
	buffer_put_cstring(&m, user ? user : "");
	buffer_put_cstring(&m, host ? host : "");
	buffer_put_string(&m, blob, len);
	buffer_put_string(&m, sig, siglen);
	buffer_put_string(&m, data, datalen);
	xfree(blob);

	mm_request_send(socket, MONITOR_REQ_KEYVERIFY, &m);

	debug3("%s: waiting for MONITOR_ANS_KEYVERIFY", __FUNCTION__);
	mm_request_receive_expect(socket, MONITOR_ANS_KEYVERIFY, &m);

	verified = buffer_get_int(&m);

	buffer_free(&m);

	return (verified);
}

/* Export key state after authentication */
Newkeys *
mm_newkeys_from_blob(u_char *blob, int blen)
{
	Buffer b;
	int rlen;
	Newkeys *newkey = NULL;
	Enc *enc;
	Mac *mac;
	Comp *comp;

	debug3("%s: %p(%d)", __FUNCTION__, blob, blen);
#ifdef DEBUG_PK
	dump_base64(stderr, blob, blen);
#endif
	buffer_init(&b);
	buffer_append(&b, blob, blen);

	newkey = xmalloc(sizeof(*newkey));
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	/* Enc structure */
	enc->name = buffer_get_string(&b, NULL);
	buffer_get(&b, &enc->cipher, sizeof(enc->cipher));
	enc->enabled = buffer_get_int(&b);
	enc->key_len = buffer_get_int(&b);
	enc->block_size = buffer_get_int(&b);
	enc->key = xmalloc(enc->key_len);
	buffer_get(&b, enc->key, enc->key_len);
	enc->iv = xmalloc(enc->block_size);
	buffer_get(&b, enc->iv, enc->block_size);

	if (enc->name == NULL || cipher_by_name(enc->name) != enc->cipher)
		fatal("%s: bad cipher name %s or pointer %p", __FUNCTION__,
		    enc->name, enc->cipher);

	/* Mac structure */
	mac->name = buffer_get_string(&b, NULL);
	if (mac->name == NULL || mac_init(mac, mac->name) == -1)
		fatal("%s: can not init mac %s", __FUNCTION__, mac->name);
	mac->enabled = buffer_get_int(&b);
	mac->key = xmalloc(mac->key_len);
	buffer_get(&b, mac->key, mac->key_len);

	/* Comp structure */
	comp->type = buffer_get_int(&b);
	comp->enabled = buffer_get_int(&b);
	comp->name = buffer_get_string(&b, NULL);

	rlen = buffer_len(&b);
	if (rlen != 0)
		error("newkeys_from_blob: remaining bytes in blob %d", rlen);
	buffer_free(&b);
	return (newkey);
}

int
mm_newkeys_to_blob(int mode, u_char **blobp, u_int *lenp)
{
	Buffer b;
	int len;
	u_char *buf;
	Enc *enc;
	Mac *mac;
	Comp *comp;
	Newkeys *newkey = newkeys[mode];

	debug3("%s: converting %p", __FUNCTION__, newkey);

	if (newkey == NULL) {
		error("%s: newkey == NULL", __FUNCTION__);
		return 0;
	}
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	buffer_init(&b);
	/* Enc structure */
	buffer_put_cstring(&b, enc->name);
	/* The cipher struct is constant and shared, you export pointer */
	buffer_append(&b, &enc->cipher, sizeof(enc->cipher));
	buffer_put_int(&b, enc->enabled);
	buffer_put_int(&b, enc->key_len);
	buffer_put_int(&b, enc->block_size);
	buffer_append(&b, enc->key, enc->key_len);
	packet_get_keyiv(mode, enc->iv, enc->block_size);
	buffer_append(&b, enc->iv, enc->block_size);

	/* Mac structure */
	buffer_put_cstring(&b, mac->name);
	buffer_put_int(&b, mac->enabled);
	buffer_append(&b, mac->key, mac->key_len);

	/* Comp structure */
	buffer_put_int(&b, comp->type);
	buffer_put_int(&b, comp->enabled);
	buffer_put_cstring(&b, comp->name);

	len = buffer_len(&b);
	buf = xmalloc(len);
	memcpy(buf, buffer_ptr(&b), len);
	memset(buffer_ptr(&b), 0, len);
	buffer_free(&b);
	if (lenp != NULL)
		*lenp = len;
	if (blobp != NULL)
		*blobp = buf;
	return len;
}

void
mm_send_keystate(int socket)
{
	Buffer m;
	u_char *blob, *p;
	u_int bloblen, plen;

	debug3("%s: Sending new keys: %p %p",
	    __FUNCTION__, newkeys[MODE_OUT], newkeys[MODE_IN]);

	buffer_init(&m);

	/* Keys from Kex */
	if (!mm_newkeys_to_blob(MODE_OUT, &blob, &bloblen))
		fatal("%s: conversion of newkeys failed", __FUNCTION__);

	buffer_put_string(&m, blob, bloblen);
	xfree(blob);

	if (!mm_newkeys_to_blob(MODE_IN, &blob, &bloblen))
		fatal("%s: conversion of newkeys failed", __FUNCTION__);

	buffer_put_string(&m, blob, bloblen);
	xfree(blob);

	buffer_put_int(&m, packet_get_seqnr(MODE_OUT));
	buffer_put_int(&m, packet_get_seqnr(MODE_IN));

	debug3("%s: New keys have been sent", __FUNCTION__);

	/* More key context */
	plen = packet_get_keycontext(MODE_OUT, NULL);
	p = xmalloc(plen+1);
	packet_get_keycontext(MODE_OUT, p);
	buffer_put_string(&m, p, plen);
	xfree(p);

	plen = packet_get_keycontext(MODE_IN, NULL);
	p = xmalloc(plen+1);
	packet_get_keycontext(MODE_IN, p);
	buffer_put_string(&m, p, plen);
	xfree(p);

	/* Compression state */
	debug3("%s: Sending compression state", __FUNCTION__);
	buffer_put_string(&m, &outgoing_stream, sizeof(outgoing_stream));
	buffer_put_string(&m, &incoming_stream, sizeof(incoming_stream));

	mm_request_send(socket, MONITOR_REQ_KEYEXPORT, &m);
	debug3("%s: Finished sending state", __FUNCTION__);

	buffer_free(&m);
}

int
mm_pty_allocown(int socket, int *ptyfd, int *ttyfd,
    char *namebuf, int namebuflen)
{
	Buffer m;
	u_char *p;
	int success = 0;

	buffer_init(&m);
	mm_request_send(socket, MONITOR_REQ_PTY, &m);

	debug3("%s: waiting for MONITOR_ANS_PTY", __FUNCTION__);
	mm_request_receive_expect(socket, MONITOR_ANS_PTY, &m);

	success = buffer_get_int(&m);
	if (success == 0) {
		debug3("%s: pty alloc failed", __FUNCTION__);
		buffer_free(&m);
		return (0);
	}
	p = buffer_get_string(&m, NULL);
	buffer_free(&m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	xfree(p);

	*ptyfd = mm_receive_fd(socket);
	*ttyfd = mm_receive_fd(socket);

	/* Success */
	return (1);
}

/* Request process termination */

void
mm_terminate(int socket)
{
	Buffer m;

	buffer_init(&m);
	mm_request_send(socket, MONITOR_REQ_TERM, &m);
	buffer_free(&m);
}
