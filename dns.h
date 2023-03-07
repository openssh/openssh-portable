/* $OpenBSD: dns.h,v 1.20 2023/02/10 04:56:30 djm Exp $ */

/*
 * Copyright (c) 2003 Wesley Griffin. All rights reserved.
 * Copyright (c) 2003 Jakob Schlyter. All rights reserved.
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

#ifndef DNS_H
#define DNS_H

enum sshfp_types {
	SSHFP_KEY_RESERVED = 0,
	SSHFP_KEY_RSA = 1,
	SSHFP_KEY_DSA = 2,
	SSHFP_KEY_ECDSA = 3,
	SSHFP_KEY_ED25519 = 4,
	/* FIXME: This is not RFC-compliant. 
	* 5 is unassigned
	www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.txt
	* RFC 8709 defines 6 as ED448.
	*/
	SSHFP_KEY_XMSS = 5,
	SSHFP_KEY_MAX = 6
};

enum sshfp_hashes {
	SSHFP_HASH_RESERVED = 0,
	SSHFP_HASH_SHA1 = 1,
	SSHFP_HASH_SHA256 = 2,
	SSHFP_HASH_MAX = 3
};

typedef struct s_sshfp_record {
	u_int8_t dnskey_algorithm;
	u_int8_t dnskey_digest_type;
	u_char *dnskey_digest;
	size_t dnskey_digest_len;
} sshfp_record_t;

#define DNS_RDATACLASS_IN	1
#define DNS_RDATATYPE_SSHFP	44

#define DNS_MAX_RECORDS		256

#define DNS_VERIFY_FOUND			0x00000001
#define DNS_VERIFY_MATCH 			0x00000002
#define DNS_VERIFY_MATCH_SHA1		0x00000004
#define DNS_VERIFY_MATCH_SHA256		0x00000008
#define DNS_VERIFY_SECURE			0x00000010
#define DNS_VERIFY_FAILED			0x00000020

int	verify_host_key_dns(const char *, struct sockaddr *,
    struct sshkey *, int *);
int	export_dns_rr(const char *, struct sshkey *, FILE *, int, int);

#endif /* DNS_H */
