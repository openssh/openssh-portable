/* $OpenBSD: ssh-sk.h,v 1.2 2019/10/31 21:22:01 djm Exp $ */
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

#ifndef _SSH_SK_H
#define _SSH_SK_H 1

struct sshbuf;
struct sshkey;

/* Version of protocol between ssh-agent and ssh-sk-helper */
#define SSH_SK_HELPER_VERSION	1

/*
 * Enroll (generate) a new security-key hosted private key via the specified
 * provider middleware.
 * If challenge_buf is NULL then a random 256 bit challenge will be used.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 *
 * If successful and the attest_data buffer is not NULL then attestation
 * information is placed there.
 */
int sshsk_enroll(const char *provider_path, const char *application,
    uint8_t flags, struct sshbuf *challenge_buf, struct sshkey **keyp,
    struct sshbuf *attest);

/*
 * Calculate an ECDSA_SK signature using the specified key and provider
 * middleware.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
int sshsk_ecdsa_sign(const char *provider_path, const struct sshkey *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    u_int compat);

#endif /* _SSH_SK_H */

