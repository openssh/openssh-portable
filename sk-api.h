/* $OpenBSD: sk-api.h,v 1.1 2019/10/31 21:16:20 djm Exp $ */
/*
 * Copyright (c) 2019 Google LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _SK_API_H
#define _SK_API_H 1

#include <stddef.h>
#include <stdint.h>

/* Flags */
#define SSH_SK_USER_PRESENCE_REQD	0x01

struct sk_enroll_response {
	uint8_t *public_key;
	size_t public_key_len;
	uint8_t *key_handle;
	size_t key_handle_len;
	uint8_t *signature;
	size_t signature_len;
	uint8_t *attestation_cert;
	size_t attestation_cert_len;
};

struct sk_sign_response {
	uint8_t flags;
	uint32_t counter;
	uint8_t *sig_r;
	size_t sig_r_len;
	uint8_t *sig_s;
	size_t sig_s_len;
};

#define SSH_SK_VERSION_MAJOR		0x00010000 /* current API version */
#define SSH_SK_VERSION_MAJOR_MASK	0xffff0000

/* Return the version of the middleware API */
uint32_t sk_api_version(void);

/* Enroll a U2F key (private key generation) */
int sk_enroll(const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags,
    struct sk_enroll_response **enroll_response);

/* Sign a challenge */
int sk_sign(const uint8_t *message, size_t message_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, struct sk_sign_response **sign_response);

#endif /* _SK_API_H */
