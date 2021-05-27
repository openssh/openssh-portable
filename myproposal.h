/* $OpenBSD: myproposal.h,v 1.67 2020/01/24 00:28:57 djm Exp $ */

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

// OQS-TODO: can we #ifdef the PQ defs in the following #define's
// OQS-TODO: should I add the PQ auth methods here? they were not added in 7.9 branch...

#define KEX_SERVER_KEX	\
	"curve25519-sha256," \
	"curve25519-sha256@libssh.org," \
	"ecdh-sha2-nistp256," \
	"ecdh-sha2-nistp384," \
	"ecdh-sha2-nistp521," \
	"diffie-hellman-group-exchange-sha256," \
	"diffie-hellman-group16-sha512," \
	"diffie-hellman-group18-sha512," \
	"diffie-hellman-group14-sha256," \
/*/// OQS_TEMPLATE_FRAGMENT_ADD_SERVER_KEXS_START */ \
	"oqs-default-sha256," \
	"ecdh-nistp256-oqs-default-sha256," \
	"frodokem-640-aes-sha256," \
	"ecdh-nistp256-frodokem-640-aes-sha256," \
	"frodokem-976-aes-sha384," \
	"ecdh-nistp384-frodokem-976-aes-sha384," \
	"frodokem-1344-aes-sha512," \
	"ecdh-nistp521-frodokem-1344-aes-sha512," \
	"frodokem-640-shake-sha256," \
	"ecdh-nistp256-frodokem-640-shake-sha256," \
	"frodokem-976-shake-sha384," \
	"ecdh-nistp384-frodokem-976-shake-sha384," \
	"frodokem-1344-shake-sha512," \
	"ecdh-nistp521-frodokem-1344-shake-sha512," \
	"sidh-p434-sha256," \
	"ecdh-nistp256-sidh-p434-sha256," \
	"sidh-p434-compressed-sha256," \
	"ecdh-nistp256-sidh-p434-compressed-sha256," \
	"sidh-p610-sha256," \
	"ecdh-nistp384-sidh-p610-sha256," \
	"sidh-p610-compressed-sha256," \
	"ecdh-nistp384-sidh-p610-compressed-sha256," \
	"sidh-p751-sha256," \
	"ecdh-nistp521-sidh-p751-sha256," \
	"sidh-p751-compressed-sha256," \
	"ecdh-nistp521-sidh-p751-compressed-sha256," \
	"sike-p434-sha256," \
	"ecdh-nistp256-sike-p434-sha256," \
	"sike-p434-compressed-sha256," \
	"ecdh-nistp256-sike-p434-compressed-sha256," \
	"sike-p610-sha256," \
	"ecdh-nistp384-sike-p610-sha256," \
	"sike-p610-compressed-sha256," \
	"ecdh-nistp384-sike-p610-compressed-sha256," \
	"sike-p751-sha256," \
	"ecdh-nistp521-sike-p751-sha256," \
	"sike-p751-compressed-sha256," \
	"ecdh-nistp521-sike-p751-compressed-sha256," \
	"saber-lightsaber-sha256," \
	"ecdh-nistp256-saber-lightsaber-sha256," \
	"saber-saber-sha384," \
	"ecdh-nistp384-saber-saber-sha384," \
	"saber-firesaber-sha512," \
	"ecdh-nistp521-saber-firesaber-sha512," \
	"kyber-512-sha256," \
	"ecdh-nistp256-kyber-512-sha256," \
	"kyber-768-sha384," \
	"ecdh-nistp384-kyber-768-sha384," \
	"kyber-1024-sha512," \
	"ecdh-nistp521-kyber-1024-sha512," \
	"kyber-512-90s-sha256," \
	"ecdh-nistp256-kyber-512-90s-sha256," \
	"kyber-768-90s-sha384," \
	"ecdh-nistp384-kyber-768-90s-sha384," \
	"kyber-1024-90s-sha512," \
	"ecdh-nistp521-kyber-1024-90s-sha512," \
	"bike1-l1-cpa-sha512," \
	"ecdh-nistp256-bike1-l1-cpa-sha512," \
	"bike1-l1-fo-sha512," \
	"ecdh-nistp256-bike1-l1-fo-sha512," \
	"bike1-l3-cpa-sha512," \
	"ecdh-nistp384-bike1-l3-cpa-sha512," \
	"bike1-l3-fo-sha512," \
	"ecdh-nistp384-bike1-l3-fo-sha512," \
	"ntru-hps2048509-sha512," \
	"ecdh-nistp256-ntru-hps2048509-sha512," \
	"ntru-hps2048677-sha512," \
	"ecdh-nistp384-ntru-hps2048677-sha512," \
	"ntru-hrss701-sha512," \
	"ecdh-nistp384-ntru-hrss701-sha512," \
	"ntru-hps4096821-sha512," \
	"ecdh-nistp521-ntru-hps4096821-sha512," \
	"classic-mceliece-348864-sha256," \
	"ecdh-nistp256-classic-mceliece-348864-sha256," \
	"classic-mceliece-348864f-sha256," \
	"ecdh-nistp256-classic-mceliece-348864f-sha256," \
	"classic-mceliece-460896-sha512," \
	"ecdh-nistp384-classic-mceliece-460896-sha512," \
	"classic-mceliece-460896f-sha512," \
	"ecdh-nistp384-classic-mceliece-460896f-sha512," \
	"classic-mceliece-6688128-sha512," \
	"ecdh-nistp521-classic-mceliece-6688128-sha512," \
	"classic-mceliece-6688128f-sha512," \
	"ecdh-nistp521-classic-mceliece-6688128f-sha512," \
	"classic-mceliece-6960119-sha512," \
	"ecdh-nistp521-classic-mceliece-6960119-sha512," \
	"classic-mceliece-6960119f-sha512," \
	"ecdh-nistp521-classic-mceliece-6960119f-sha512," \
	"classic-mceliece-8192128-sha512," \
	"ecdh-nistp521-classic-mceliece-8192128-sha512," \
	"classic-mceliece-8192128f-sha512," \
	"ecdh-nistp521-classic-mceliece-8192128f-sha512," \
	"hqc-128-sha256," \
	"ecdh-nistp256-hqc-128-sha256," \
	"hqc-192-sha384," \
	"ecdh-nistp384-hqc-192-sha384," \
	"hqc-256-sha512," \
	"ecdh-nistp521-hqc-256-sha512," \
	"ntruprime-ntrulpr653-sha256," \
	"ecdh-nistp256-ntruprime-ntrulpr653-sha256," \
	"ntruprime-sntrup653-sha256," \
	"ecdh-nistp256-ntruprime-sntrup653-sha256," \
	"ntruprime-ntrulpr761-sha384," \
	"ecdh-nistp384-ntruprime-ntrulpr761-sha384," \
	"ntruprime-sntrup761-sha384," \
	"ecdh-nistp384-ntruprime-sntrup761-sha384," \
	"ntruprime-ntrulpr857-sha384," \
	"ecdh-nistp384-ntruprime-ntrulpr857-sha384," \
	"ntruprime-sntrup857-sha384," \
	"ecdh-nistp384-ntruprime-sntrup857-sha384"
/*/// OQS_TEMPLATE_FRAGMENT_ADD_SERVER_KEXS_END */

#define KEX_CLIENT_KEX KEX_SERVER_KEX

#define	KEX_DEFAULT_PK_ALG	\
	"ecdsa-sha2-nistp256-cert-v01@openssh.com," \
	"ecdsa-sha2-nistp384-cert-v01@openssh.com," \
	"ecdsa-sha2-nistp521-cert-v01@openssh.com," \
	"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com," \
	"ssh-ed25519-cert-v01@openssh.com," \
	"sk-ssh-ed25519-cert-v01@openssh.com," \
	"rsa-sha2-512-cert-v01@openssh.com," \
	"rsa-sha2-256-cert-v01@openssh.com," \
	"ssh-rsa-cert-v01@openssh.com," \
	"ecdsa-sha2-nistp256," \
	"ecdsa-sha2-nistp384," \
	"ecdsa-sha2-nistp521," \
	"sk-ecdsa-sha2-nistp256@openssh.com," \
	"ssh-ed25519," \
	"sk-ssh-ed25519@openssh.com," \
	"rsa-sha2-512," \
	"rsa-sha2-256," \
	"ssh-rsa"

#define	KEX_SERVER_ENCRYPT \
	"chacha20-poly1305@openssh.com," \
	"aes128-ctr,aes192-ctr,aes256-ctr," \
	"aes128-gcm@openssh.com,aes256-gcm@openssh.com"

#define KEX_CLIENT_ENCRYPT KEX_SERVER_ENCRYPT

#define	KEX_SERVER_MAC \
	"umac-64-etm@openssh.com," \
	"umac-128-etm@openssh.com," \
	"hmac-sha2-256-etm@openssh.com," \
	"hmac-sha2-512-etm@openssh.com," \
	"hmac-sha1-etm@openssh.com," \
	"umac-64@openssh.com," \
	"umac-128@openssh.com," \
	"hmac-sha2-256," \
	"hmac-sha2-512," \
	"hmac-sha1"

#define KEX_CLIENT_MAC KEX_SERVER_MAC

/* Not a KEX value, but here so all the algorithm defaults are together */
#define	SSH_ALLOWED_CA_SIGALGS	\
	"ecdsa-sha2-nistp256," \
	"ecdsa-sha2-nistp384," \
	"ecdsa-sha2-nistp521," \
	"sk-ecdsa-sha2-nistp256@openssh.com," \
	"ssh-ed25519," \
	"sk-ssh-ed25519@openssh.com," \
	"rsa-sha2-512," \
	"rsa-sha2-256"

#define	KEX_DEFAULT_COMP	"none,zlib@openssh.com"
#define	KEX_DEFAULT_LANG	""

#define KEX_CLIENT \
	KEX_CLIENT_KEX, \
	KEX_DEFAULT_PK_ALG, \
	KEX_CLIENT_ENCRYPT, \
	KEX_CLIENT_ENCRYPT, \
	KEX_CLIENT_MAC, \
	KEX_CLIENT_MAC, \
	KEX_DEFAULT_COMP, \
	KEX_DEFAULT_COMP, \
	KEX_DEFAULT_LANG, \
	KEX_DEFAULT_LANG

#define KEX_SERVER \
	KEX_SERVER_KEX, \
	KEX_DEFAULT_PK_ALG, \
	KEX_SERVER_ENCRYPT, \
	KEX_SERVER_ENCRYPT, \
	KEX_SERVER_MAC, \
	KEX_SERVER_MAC, \
	KEX_DEFAULT_COMP, \
	KEX_DEFAULT_COMP, \
	KEX_DEFAULT_LANG, \
	KEX_DEFAULT_LANG
