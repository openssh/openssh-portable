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

#ifndef _MONITOR_H_
#define _MONITOR_H_

enum monitor_reqtype {
	MONITOR_REQ_MODULI, MONITOR_ANS_MODULI,
	MONITOR_REQ_FREE, MONITOR_REQ_AUTHSERV,
	MONITOR_REQ_SIGN, MONITOR_ANS_SIGN,
	MONITOR_REQ_PWNAM, MONITOR_ANS_PWNAM,
	MONITOR_REQ_AUTHPASSWORD, MONITOR_ANS_AUTHPASSWORD,
	MONITOR_REQ_KEYALLOWED, MONITOR_ANS_KEYALLOWED,
	MONITOR_REQ_KEYVERIFY, MONITOR_ANS_KEYVERIFY,
	MONITOR_REQ_KEYEXPORT,
	MONITOR_REQ_PTY, MONITOR_ANS_PTY,
	MONITOR_REQ_TERM
};

struct monitor_req {
	enum monitor_reqtype type;
	void *address;
	size_t size;
};

void monitor_socketpair(int *pair);

struct Authctxt;
struct Authctxt *monitor_child_preauth(int);
void monitor_child_postauth(int);

struct mon_table;
int monitor_read(int, struct mon_table *);

#endif /* _MONITOR_H_ */
