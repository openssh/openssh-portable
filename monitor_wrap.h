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

#ifndef _MM_WRAP_H_
#define _MM_WRAP_H_
#include "key.h"
#include "buffer.h"

struct mm_moduli {
	int min;
	int want;
	int max;
};

enum mm_keytype {MM_HOSTKEY, MM_USERKEY};

struct mm_keyallowed {
	enum mm_keytype type;
	char chost[MAXHOSTNAMELEN];
	char cuser[MAXLOGNAME];
};

struct mm_master;

struct passwd;
DH *mm_choose_dh(int, int, int, int);
DH *mm_read_moduli(int);
int mm_key_sign(int, int, u_char **, u_int *, u_char *, u_int);
void mm_inform_authserv(int, char *, char *);
struct passwd *mm_getpwnamallow(int, const char *, int *);
int mm_auth_password(int, char *);
int mm_key_allowed(int, enum mm_keytype, char *, char *, Key *);
#define mm_hostbased_key_allowed(x,u,h,z) \
	mm_key_allowed(x, MM_HOSTKEY, u, h, z)
#define mm_user_key_allowed(x,z) \
	mm_key_allowed(x, MM_USERKEY, NULL, NULL, z)

int mm_key_verify(int, enum mm_keytype, char *, char *,
    Key *, u_char *, u_int, u_char *, u_int);

void mm_terminate(int);

/* Key export functions */
struct Newkeys *mm_newkeys_from_blob(u_char *, int);
int mm_newkeys_to_blob(int, u_char **, u_int *);

void mm_apply_keystate(struct mm_master *);
void mm_get_keystate(int);
void mm_send_keystate(int);

int mm_pty_allocown(int, int *, int *, char *, int);

/* Functions on the montior that answer unprivileged requests */

int mm_answer_moduli(int, Buffer *);
int mm_answer_sign(int, Buffer *);
int mm_answer_pwnamallow(int, Buffer *);
int mm_answer_authserv(int, Buffer *);
int mm_answer_authpassword(int, Buffer *);
int mm_answer_keyallowed(int, Buffer *);
int mm_answer_keyverify(int, Buffer *);
int mm_answer_pty(int, Buffer *);
int mm_answer_term(int, Buffer *);

void mm_request_send(int , enum monitor_reqtype, Buffer *);
void mm_request_receive(int, Buffer *);
void mm_request_receive_expect(int, enum monitor_reqtype,
    Buffer *);

void *mm_zalloc(struct mm_master *, u_int, u_int);
void mm_zfree(struct mm_master *, void *);
void mm_init_compression(struct mm_master *);

/* Utility functions */

void pwfree(struct passwd *);
#endif /* _MM_H_ */
