/* $OpenBSD: kexgen.c,v 1.4 2019/11/25 00:51:37 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "oqs/oqs.h"

static int input_kex_gen_init(int, u_int32_t, struct ssh *);
static int input_kex_gen_reply(int type, u_int32_t seq, struct ssh *ssh);

static int
kex_gen_hash(
    int hash_alg,
    const struct sshbuf *client_version,
    const struct sshbuf *server_version,
    const struct sshbuf *client_kexinit,
    const struct sshbuf *server_kexinit,
    const struct sshbuf *server_host_key_blob,
    const struct sshbuf *client_pub,
    const struct sshbuf *server_pub,
    const struct sshbuf *shared_secret,
    u_char *hash, size_t *hashlen)
{
	struct sshbuf *b;
	int r;

	if (*hashlen < ssh_digest_bytes(hash_alg))
		return SSH_ERR_INVALID_ARGUMENT;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_key_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		return r;
	}
#ifdef DEBUG_KEX
	sshbuf_dump(b, stderr);
#endif
	if (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	return 0;
}

int
kex_gen_client(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	int r;

	switch (kex->kex_type) {
#ifdef WITH_OPENSSL
	case KEX_DH_GRP1_SHA1:
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
	case KEX_DH_GRP16_SHA512:
	case KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		break;
	case KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		break;
#endif
	case KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		break;
	case KEX_KEM_SNTRUP4591761X25519_SHA512:
		r = kex_kem_sntrup4591761x25519_keypair(kex);
		break;
///// OQS_TEMPLATE_FRAGMENT_ADD_CLIENT_SWITCH_CASES_START
	case KEX_KEM_OQS_DEFAULT_SHA256:
		r = kex_kem_oqs_default_keypair(kex);
		break;
	case KEX_KEM_FRODOKEM_640_AES_SHA256:
		r = kex_kem_frodokem_640_aes_keypair(kex);
		break;
	case KEX_KEM_FRODOKEM_976_AES_SHA384:
		r = kex_kem_frodokem_976_aes_keypair(kex);
		break;
	case KEX_KEM_FRODOKEM_1344_AES_SHA512:
		r = kex_kem_frodokem_1344_aes_keypair(kex);
		break;
	case KEX_KEM_FRODOKEM_640_SHAKE_SHA256:
		r = kex_kem_frodokem_640_shake_keypair(kex);
		break;
	case KEX_KEM_FRODOKEM_976_SHAKE_SHA384:
		r = kex_kem_frodokem_976_shake_keypair(kex);
		break;
	case KEX_KEM_FRODOKEM_1344_SHAKE_SHA512:
		r = kex_kem_frodokem_1344_shake_keypair(kex);
		break;
	case KEX_KEM_SIDH_P434_SHA256:
		r = kex_kem_sidh_p434_keypair(kex);
		break;
	case KEX_KEM_SIDH_P434_COMPRESSED_SHA256:
		r = kex_kem_sidh_p434_compressed_keypair(kex);
		break;
	case KEX_KEM_SIDH_P610_SHA256:
		r = kex_kem_sidh_p610_keypair(kex);
		break;
	case KEX_KEM_SIDH_P610_COMPRESSED_SHA256:
		r = kex_kem_sidh_p610_compressed_keypair(kex);
		break;
	case KEX_KEM_SIDH_P751_SHA256:
		r = kex_kem_sidh_p751_keypair(kex);
		break;
	case KEX_KEM_SIDH_P751_COMPRESSED_SHA256:
		r = kex_kem_sidh_p751_compressed_keypair(kex);
		break;
	case KEX_KEM_SIKE_P434_SHA256:
		r = kex_kem_sike_p434_keypair(kex);
		break;
	case KEX_KEM_SIKE_P434_COMPRESSED_SHA256:
		r = kex_kem_sike_p434_compressed_keypair(kex);
		break;
	case KEX_KEM_SIKE_P610_SHA256:
		r = kex_kem_sike_p610_keypair(kex);
		break;
	case KEX_KEM_SIKE_P610_COMPRESSED_SHA256:
		r = kex_kem_sike_p610_compressed_keypair(kex);
		break;
	case KEX_KEM_SIKE_P751_SHA256:
		r = kex_kem_sike_p751_keypair(kex);
		break;
	case KEX_KEM_SIKE_P751_COMPRESSED_SHA256:
		r = kex_kem_sike_p751_compressed_keypair(kex);
		break;
	case KEX_KEM_SABER_LIGHTSABER_SHA256:
		r = kex_kem_saber_lightsaber_keypair(kex);
		break;
	case KEX_KEM_SABER_SABER_SHA384:
		r = kex_kem_saber_saber_keypair(kex);
		break;
	case KEX_KEM_SABER_FIRESABER_SHA512:
		r = kex_kem_saber_firesaber_keypair(kex);
		break;
	case KEX_KEM_KYBER_512_SHA256:
		r = kex_kem_kyber_512_keypair(kex);
		break;
	case KEX_KEM_KYBER_768_SHA384:
		r = kex_kem_kyber_768_keypair(kex);
		break;
	case KEX_KEM_KYBER_1024_SHA512:
		r = kex_kem_kyber_1024_keypair(kex);
		break;
	case KEX_KEM_KYBER_512_90S_SHA256:
		r = kex_kem_kyber_512_90s_keypair(kex);
		break;
	case KEX_KEM_KYBER_768_90S_SHA384:
		r = kex_kem_kyber_768_90s_keypair(kex);
		break;
	case KEX_KEM_KYBER_1024_90S_SHA512:
		r = kex_kem_kyber_1024_90s_keypair(kex);
		break;
	case KEX_KEM_BIKE1_L1_CPA_SHA512:
		r = kex_kem_bike1_l1_cpa_keypair(kex);
		break;
	case KEX_KEM_BIKE1_L1_FO_SHA512:
		r = kex_kem_bike1_l1_fo_keypair(kex);
		break;
	case KEX_KEM_BIKE1_L3_CPA_SHA512:
		r = kex_kem_bike1_l3_cpa_keypair(kex);
		break;
	case KEX_KEM_BIKE1_L3_FO_SHA512:
		r = kex_kem_bike1_l3_fo_keypair(kex);
		break;
	case KEX_KEM_NTRU_HPS2048509_SHA512:
		r = kex_kem_ntru_hps2048509_keypair(kex);
		break;
	case KEX_KEM_NTRU_HPS2048677_SHA512:
		r = kex_kem_ntru_hps2048677_keypair(kex);
		break;
	case KEX_KEM_NTRU_HRSS701_SHA512:
		r = kex_kem_ntru_hrss701_keypair(kex);
		break;
	case KEX_KEM_NTRU_HPS4096821_SHA512:
		r = kex_kem_ntru_hps4096821_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_348864_SHA256:
		r = kex_kem_classic_mceliece_348864_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_348864F_SHA256:
		r = kex_kem_classic_mceliece_348864f_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_460896_SHA512:
		r = kex_kem_classic_mceliece_460896_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_460896F_SHA512:
		r = kex_kem_classic_mceliece_460896f_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6688128_SHA512:
		r = kex_kem_classic_mceliece_6688128_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6688128F_SHA512:
		r = kex_kem_classic_mceliece_6688128f_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6960119_SHA512:
		r = kex_kem_classic_mceliece_6960119_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6960119F_SHA512:
		r = kex_kem_classic_mceliece_6960119f_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_8192128_SHA512:
		r = kex_kem_classic_mceliece_8192128_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_8192128F_SHA512:
		r = kex_kem_classic_mceliece_8192128f_keypair(kex);
		break;
	case KEX_KEM_HQC_128_SHA256:
		r = kex_kem_hqc_128_keypair(kex);
		break;
	case KEX_KEM_HQC_192_SHA384:
		r = kex_kem_hqc_192_keypair(kex);
		break;
	case KEX_KEM_HQC_256_SHA512:
		r = kex_kem_hqc_256_keypair(kex);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR653_SHA256:
		r = kex_kem_ntruprime_ntrulpr653_keypair(kex);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP653_SHA256:
		r = kex_kem_ntruprime_sntrup653_keypair(kex);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR761_SHA384:
		r = kex_kem_ntruprime_ntrulpr761_keypair(kex);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP761_SHA384:
		r = kex_kem_ntruprime_sntrup761_keypair(kex);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR857_SHA384:
		r = kex_kem_ntruprime_ntrulpr857_keypair(kex);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP857_SHA384:
		r = kex_kem_ntruprime_sntrup857_keypair(kex);
		break;
#ifdef WITH_OPENSSL
#ifdef OPENSSL_HAS_ECC
	case KEX_KEM_OQS_DEFAULT_ECDH_NISTP256_SHA256:
		r = kex_kem_oqs_default_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_FRODOKEM_640_AES_ECDH_NISTP256_SHA256:
		r = kex_kem_frodokem_640_aes_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_FRODOKEM_976_AES_ECDH_NISTP384_SHA384:
		r = kex_kem_frodokem_976_aes_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_FRODOKEM_1344_AES_ECDH_NISTP521_SHA512:
		r = kex_kem_frodokem_1344_aes_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_FRODOKEM_640_SHAKE_ECDH_NISTP256_SHA256:
		r = kex_kem_frodokem_640_shake_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_FRODOKEM_976_SHAKE_ECDH_NISTP384_SHA384:
		r = kex_kem_frodokem_976_shake_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_FRODOKEM_1344_SHAKE_ECDH_NISTP521_SHA512:
		r = kex_kem_frodokem_1344_shake_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_SIDH_P434_ECDH_NISTP256_SHA256:
		r = kex_kem_sidh_p434_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_SIDH_P434_COMPRESSED_ECDH_NISTP256_SHA256:
		r = kex_kem_sidh_p434_compressed_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_SIDH_P610_ECDH_NISTP384_SHA256:
		r = kex_kem_sidh_p610_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_SIDH_P610_COMPRESSED_ECDH_NISTP384_SHA256:
		r = kex_kem_sidh_p610_compressed_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_SIDH_P751_ECDH_NISTP521_SHA256:
		r = kex_kem_sidh_p751_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_SIDH_P751_COMPRESSED_ECDH_NISTP521_SHA256:
		r = kex_kem_sidh_p751_compressed_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_SIKE_P434_ECDH_NISTP256_SHA256:
		r = kex_kem_sike_p434_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_SIKE_P434_COMPRESSED_ECDH_NISTP256_SHA256:
		r = kex_kem_sike_p434_compressed_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_SIKE_P610_ECDH_NISTP384_SHA256:
		r = kex_kem_sike_p610_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_SIKE_P610_COMPRESSED_ECDH_NISTP384_SHA256:
		r = kex_kem_sike_p610_compressed_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_SIKE_P751_ECDH_NISTP521_SHA256:
		r = kex_kem_sike_p751_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_SIKE_P751_COMPRESSED_ECDH_NISTP521_SHA256:
		r = kex_kem_sike_p751_compressed_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_SABER_LIGHTSABER_ECDH_NISTP256_SHA256:
		r = kex_kem_saber_lightsaber_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_SABER_SABER_ECDH_NISTP384_SHA384:
		r = kex_kem_saber_saber_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_SABER_FIRESABER_ECDH_NISTP521_SHA512:
		r = kex_kem_saber_firesaber_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_KYBER_512_ECDH_NISTP256_SHA256:
		r = kex_kem_kyber_512_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_KYBER_768_ECDH_NISTP384_SHA384:
		r = kex_kem_kyber_768_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_KYBER_1024_ECDH_NISTP521_SHA512:
		r = kex_kem_kyber_1024_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_KYBER_512_90S_ECDH_NISTP256_SHA256:
		r = kex_kem_kyber_512_90s_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_KYBER_768_90S_ECDH_NISTP384_SHA384:
		r = kex_kem_kyber_768_90s_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_KYBER_1024_90S_ECDH_NISTP521_SHA512:
		r = kex_kem_kyber_1024_90s_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_BIKE1_L1_CPA_ECDH_NISTP256_SHA512:
		r = kex_kem_bike1_l1_cpa_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_BIKE1_L1_FO_ECDH_NISTP256_SHA512:
		r = kex_kem_bike1_l1_fo_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_BIKE1_L3_CPA_ECDH_NISTP384_SHA512:
		r = kex_kem_bike1_l3_cpa_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_BIKE1_L3_FO_ECDH_NISTP384_SHA512:
		r = kex_kem_bike1_l3_fo_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_NTRU_HPS2048509_ECDH_NISTP256_SHA512:
		r = kex_kem_ntru_hps2048509_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_NTRU_HPS2048677_ECDH_NISTP384_SHA512:
		r = kex_kem_ntru_hps2048677_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_NTRU_HRSS701_ECDH_NISTP384_SHA512:
		r = kex_kem_ntru_hrss701_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_NTRU_HPS4096821_ECDH_NISTP521_SHA512:
		r = kex_kem_ntru_hps4096821_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_348864_ECDH_NISTP256_SHA256:
		r = kex_kem_classic_mceliece_348864_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_348864F_ECDH_NISTP256_SHA256:
		r = kex_kem_classic_mceliece_348864f_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_460896_ECDH_NISTP384_SHA512:
		r = kex_kem_classic_mceliece_460896_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_460896F_ECDH_NISTP384_SHA512:
		r = kex_kem_classic_mceliece_460896f_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6688128_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_6688128_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6688128F_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_6688128f_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6960119_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_6960119_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6960119F_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_6960119f_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_8192128_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_8192128_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_8192128F_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_8192128f_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_HQC_128_ECDH_NISTP256_SHA256:
		r = kex_kem_hqc_128_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_HQC_192_ECDH_NISTP384_SHA384:
		r = kex_kem_hqc_192_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_HQC_256_ECDH_NISTP521_SHA512:
		r = kex_kem_hqc_256_ecdh_nistp521_keypair(kex);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR653_ECDH_NISTP256_SHA256:
		r = kex_kem_ntruprime_ntrulpr653_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP653_ECDH_NISTP256_SHA256:
		r = kex_kem_ntruprime_sntrup653_ecdh_nistp256_keypair(kex);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR761_ECDH_NISTP384_SHA384:
		r = kex_kem_ntruprime_ntrulpr761_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP761_ECDH_NISTP384_SHA384:
		r = kex_kem_ntruprime_sntrup761_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR857_ECDH_NISTP384_SHA384:
		r = kex_kem_ntruprime_ntrulpr857_ecdh_nistp384_keypair(kex);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP857_ECDH_NISTP384_SHA384:
		r = kex_kem_ntruprime_sntrup857_ecdh_nistp384_keypair(kex);
		break;
#endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */
///// OQS_TEMPLATE_FRAGMENT_ADD_CLIENT_SWITCH_CASES_END
	default:
		r = SSH_ERR_INVALID_ARGUMENT;
		break;
	}
	if (r != 0)
		return r;
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		return r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_ECDH_REPLY, &input_kex_gen_reply);
	return 0;
}

static int
input_kex_gen_reply(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	struct sshkey *server_host_key = NULL;
	struct sshbuf *shared_secret = NULL;
	struct sshbuf *server_blob = NULL;
	struct sshbuf *tmp = NULL, *server_host_key_blob = NULL;
	u_char *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	int r;

	/* hostkey */
	if ((r = sshpkt_getb_froms(ssh, &server_host_key_blob)) != 0)
		goto out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	if ((tmp = sshbuf_fromb(server_host_key_blob)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_fromb(tmp, &server_host_key)) != 0)
		goto out;
	if ((r = kex_verify_host_key(ssh, server_host_key)) != 0)
		goto out;

	/* Q_S, server public key */
	/* signed H */
	if ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;

	/* compute shared secret */
	switch (kex->kex_type) {
#ifdef WITH_OPENSSL
	case KEX_DH_GRP1_SHA1:
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
	case KEX_DH_GRP16_SHA512:
	case KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		break;
#endif
	case KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SNTRUP4591761X25519_SHA512:
		r = kex_kem_sntrup4591761x25519_dec(kex, server_blob,
		    &shared_secret);
		break;
///// OQS_TEMPLATE_FRAGMENT_ADD_REPLY_SWITCH_CASES_START
	case KEX_KEM_OQS_DEFAULT_SHA256:
		r = kex_kem_oqs_default_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_640_AES_SHA256:
		r = kex_kem_frodokem_640_aes_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_976_AES_SHA384:
		r = kex_kem_frodokem_976_aes_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_1344_AES_SHA512:
		r = kex_kem_frodokem_1344_aes_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_640_SHAKE_SHA256:
		r = kex_kem_frodokem_640_shake_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_976_SHAKE_SHA384:
		r = kex_kem_frodokem_976_shake_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_1344_SHAKE_SHA512:
		r = kex_kem_frodokem_1344_shake_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIDH_P434_SHA256:
		r = kex_kem_sidh_p434_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIDH_P434_COMPRESSED_SHA256:
		r = kex_kem_sidh_p434_compressed_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIDH_P610_SHA256:
		r = kex_kem_sidh_p610_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIDH_P610_COMPRESSED_SHA256:
		r = kex_kem_sidh_p610_compressed_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIDH_P751_SHA256:
		r = kex_kem_sidh_p751_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIDH_P751_COMPRESSED_SHA256:
		r = kex_kem_sidh_p751_compressed_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIKE_P434_SHA256:
		r = kex_kem_sike_p434_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIKE_P434_COMPRESSED_SHA256:
		r = kex_kem_sike_p434_compressed_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIKE_P610_SHA256:
		r = kex_kem_sike_p610_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIKE_P610_COMPRESSED_SHA256:
		r = kex_kem_sike_p610_compressed_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIKE_P751_SHA256:
		r = kex_kem_sike_p751_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIKE_P751_COMPRESSED_SHA256:
		r = kex_kem_sike_p751_compressed_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SABER_LIGHTSABER_SHA256:
		r = kex_kem_saber_lightsaber_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SABER_SABER_SHA384:
		r = kex_kem_saber_saber_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SABER_FIRESABER_SHA512:
		r = kex_kem_saber_firesaber_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_KYBER_512_SHA256:
		r = kex_kem_kyber_512_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_KYBER_768_SHA384:
		r = kex_kem_kyber_768_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_KYBER_1024_SHA512:
		r = kex_kem_kyber_1024_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_KYBER_512_90S_SHA256:
		r = kex_kem_kyber_512_90s_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_KYBER_768_90S_SHA384:
		r = kex_kem_kyber_768_90s_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_KYBER_1024_90S_SHA512:
		r = kex_kem_kyber_1024_90s_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L1_CPA_SHA512:
		r = kex_kem_bike1_l1_cpa_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L1_FO_SHA512:
		r = kex_kem_bike1_l1_fo_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L3_CPA_SHA512:
		r = kex_kem_bike1_l3_cpa_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L3_FO_SHA512:
		r = kex_kem_bike1_l3_fo_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRU_HPS2048509_SHA512:
		r = kex_kem_ntru_hps2048509_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRU_HPS2048677_SHA512:
		r = kex_kem_ntru_hps2048677_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRU_HRSS701_SHA512:
		r = kex_kem_ntru_hrss701_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRU_HPS4096821_SHA512:
		r = kex_kem_ntru_hps4096821_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_348864_SHA256:
		r = kex_kem_classic_mceliece_348864_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_348864F_SHA256:
		r = kex_kem_classic_mceliece_348864f_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_460896_SHA512:
		r = kex_kem_classic_mceliece_460896_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_460896F_SHA512:
		r = kex_kem_classic_mceliece_460896f_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6688128_SHA512:
		r = kex_kem_classic_mceliece_6688128_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6688128F_SHA512:
		r = kex_kem_classic_mceliece_6688128f_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6960119_SHA512:
		r = kex_kem_classic_mceliece_6960119_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6960119F_SHA512:
		r = kex_kem_classic_mceliece_6960119f_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_8192128_SHA512:
		r = kex_kem_classic_mceliece_8192128_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_8192128F_SHA512:
		r = kex_kem_classic_mceliece_8192128f_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_HQC_128_SHA256:
		r = kex_kem_hqc_128_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_HQC_192_SHA384:
		r = kex_kem_hqc_192_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_HQC_256_SHA512:
		r = kex_kem_hqc_256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR653_SHA256:
		r = kex_kem_ntruprime_ntrulpr653_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP653_SHA256:
		r = kex_kem_ntruprime_sntrup653_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR761_SHA384:
		r = kex_kem_ntruprime_ntrulpr761_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP761_SHA384:
		r = kex_kem_ntruprime_sntrup761_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR857_SHA384:
		r = kex_kem_ntruprime_ntrulpr857_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP857_SHA384:
		r = kex_kem_ntruprime_sntrup857_dec(kex, server_blob, &shared_secret);
		break;
#ifdef WITH_OPENSSL
#ifdef OPENSSL_HAS_ECC
	case KEX_KEM_OQS_DEFAULT_ECDH_NISTP256_SHA256:
		r = kex_kem_oqs_default_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_640_AES_ECDH_NISTP256_SHA256:
		r = kex_kem_frodokem_640_aes_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_976_AES_ECDH_NISTP384_SHA384:
		r = kex_kem_frodokem_976_aes_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_1344_AES_ECDH_NISTP521_SHA512:
		r = kex_kem_frodokem_1344_aes_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_640_SHAKE_ECDH_NISTP256_SHA256:
		r = kex_kem_frodokem_640_shake_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_976_SHAKE_ECDH_NISTP384_SHA384:
		r = kex_kem_frodokem_976_shake_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_1344_SHAKE_ECDH_NISTP521_SHA512:
		r = kex_kem_frodokem_1344_shake_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIDH_P434_ECDH_NISTP256_SHA256:
		r = kex_kem_sidh_p434_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIDH_P434_COMPRESSED_ECDH_NISTP256_SHA256:
		r = kex_kem_sidh_p434_compressed_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIDH_P610_ECDH_NISTP384_SHA256:
		r = kex_kem_sidh_p610_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIDH_P610_COMPRESSED_ECDH_NISTP384_SHA256:
		r = kex_kem_sidh_p610_compressed_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIDH_P751_ECDH_NISTP521_SHA256:
		r = kex_kem_sidh_p751_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIDH_P751_COMPRESSED_ECDH_NISTP521_SHA256:
		r = kex_kem_sidh_p751_compressed_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIKE_P434_ECDH_NISTP256_SHA256:
		r = kex_kem_sike_p434_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIKE_P434_COMPRESSED_ECDH_NISTP256_SHA256:
		r = kex_kem_sike_p434_compressed_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIKE_P610_ECDH_NISTP384_SHA256:
		r = kex_kem_sike_p610_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIKE_P610_COMPRESSED_ECDH_NISTP384_SHA256:
		r = kex_kem_sike_p610_compressed_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIKE_P751_ECDH_NISTP521_SHA256:
		r = kex_kem_sike_p751_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SIKE_P751_COMPRESSED_ECDH_NISTP521_SHA256:
		r = kex_kem_sike_p751_compressed_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SABER_LIGHTSABER_ECDH_NISTP256_SHA256:
		r = kex_kem_saber_lightsaber_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SABER_SABER_ECDH_NISTP384_SHA384:
		r = kex_kem_saber_saber_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SABER_FIRESABER_ECDH_NISTP521_SHA512:
		r = kex_kem_saber_firesaber_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_KYBER_512_ECDH_NISTP256_SHA256:
		r = kex_kem_kyber_512_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_KYBER_768_ECDH_NISTP384_SHA384:
		r = kex_kem_kyber_768_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_KYBER_1024_ECDH_NISTP521_SHA512:
		r = kex_kem_kyber_1024_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_KYBER_512_90S_ECDH_NISTP256_SHA256:
		r = kex_kem_kyber_512_90s_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_KYBER_768_90S_ECDH_NISTP384_SHA384:
		r = kex_kem_kyber_768_90s_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_KYBER_1024_90S_ECDH_NISTP521_SHA512:
		r = kex_kem_kyber_1024_90s_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L1_CPA_ECDH_NISTP256_SHA512:
		r = kex_kem_bike1_l1_cpa_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L1_FO_ECDH_NISTP256_SHA512:
		r = kex_kem_bike1_l1_fo_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L3_CPA_ECDH_NISTP384_SHA512:
		r = kex_kem_bike1_l3_cpa_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L3_FO_ECDH_NISTP384_SHA512:
		r = kex_kem_bike1_l3_fo_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRU_HPS2048509_ECDH_NISTP256_SHA512:
		r = kex_kem_ntru_hps2048509_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRU_HPS2048677_ECDH_NISTP384_SHA512:
		r = kex_kem_ntru_hps2048677_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRU_HRSS701_ECDH_NISTP384_SHA512:
		r = kex_kem_ntru_hrss701_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRU_HPS4096821_ECDH_NISTP521_SHA512:
		r = kex_kem_ntru_hps4096821_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_348864_ECDH_NISTP256_SHA256:
		r = kex_kem_classic_mceliece_348864_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_348864F_ECDH_NISTP256_SHA256:
		r = kex_kem_classic_mceliece_348864f_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_460896_ECDH_NISTP384_SHA512:
		r = kex_kem_classic_mceliece_460896_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_460896F_ECDH_NISTP384_SHA512:
		r = kex_kem_classic_mceliece_460896f_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6688128_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_6688128_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6688128F_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_6688128f_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6960119_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_6960119_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6960119F_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_6960119f_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_8192128_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_8192128_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_8192128F_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_8192128f_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_HQC_128_ECDH_NISTP256_SHA256:
		r = kex_kem_hqc_128_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_HQC_192_ECDH_NISTP384_SHA384:
		r = kex_kem_hqc_192_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_HQC_256_ECDH_NISTP521_SHA512:
		r = kex_kem_hqc_256_ecdh_nistp521_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR653_ECDH_NISTP256_SHA256:
		r = kex_kem_ntruprime_ntrulpr653_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP653_ECDH_NISTP256_SHA256:
		r = kex_kem_ntruprime_sntrup653_ecdh_nistp256_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR761_ECDH_NISTP384_SHA384:
		r = kex_kem_ntruprime_ntrulpr761_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP761_ECDH_NISTP384_SHA384:
		r = kex_kem_ntruprime_sntrup761_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR857_ECDH_NISTP384_SHA384:
		r = kex_kem_ntruprime_ntrulpr857_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP857_ECDH_NISTP384_SHA384:
		r = kex_kem_ntruprime_sntrup857_ecdh_nistp384_dec(kex, server_blob, &shared_secret);
		break;
#endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */
///// OQS_TEMPLATE_FRAGMENT_ADD_REPLY_SWITCH_CASES_END
	default:
		r = SSH_ERR_INVALID_ARGUMENT;
		break;
	}
	if (r !=0 )
		goto out;

	/* calc and verify H */
	hashlen = sizeof(hash);
	if ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_key_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		goto out;

	if ((r = sshkey_verify(server_host_key, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, NULL)) != 0)
		goto out;

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);
out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(kex->c25519_client_key, sizeof(kex->c25519_client_key));
	explicit_bzero(kex->sntrup4591761_client_key,
	    sizeof(kex->sntrup4591761_client_key));
	if (kex->oqs_client_key) {
	  explicit_bzero(kex->oqs_client_key, kex->oqs_client_key_size);
	  free(kex->oqs_client_key);
	  kex->oqs_client_key = NULL;
	}
	sshbuf_free(server_host_key_blob);
	free(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_key);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = NULL;
	return r;
}

int
kex_gen_server(struct ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_ECDH_INIT, &input_kex_gen_init);
	return 0;
}

static int
input_kex_gen_init(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	struct sshkey *server_host_private, *server_host_public;
	struct sshbuf *shared_secret = NULL;
	struct sshbuf *server_pubkey = NULL;
	struct sshbuf *client_pubkey = NULL;
	struct sshbuf *server_host_key_blob = NULL;
	u_char *signature = NULL, hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	int r;

	if ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		goto out;

	if ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;

	/* compute shared secret */
	switch (kex->kex_type) {
#ifdef WITH_OPENSSL
	case KEX_DH_GRP1_SHA1:
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
	case KEX_DH_GRP16_SHA512:
	case KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		break;
	case KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		break;
#endif
	case KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		break;
	case KEX_KEM_SNTRUP4591761X25519_SHA512:
		r = kex_kem_sntrup4591761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
///// OQS_TEMPLATE_FRAGMENT_ADD_INIT_SWITCH_CASES_START
	case KEX_KEM_OQS_DEFAULT_SHA256:
		r = kex_kem_oqs_default_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_640_AES_SHA256:
		r = kex_kem_frodokem_640_aes_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_976_AES_SHA384:
		r = kex_kem_frodokem_976_aes_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_1344_AES_SHA512:
		r = kex_kem_frodokem_1344_aes_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_640_SHAKE_SHA256:
		r = kex_kem_frodokem_640_shake_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_976_SHAKE_SHA384:
		r = kex_kem_frodokem_976_shake_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_1344_SHAKE_SHA512:
		r = kex_kem_frodokem_1344_shake_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIDH_P434_SHA256:
		r = kex_kem_sidh_p434_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIDH_P434_COMPRESSED_SHA256:
		r = kex_kem_sidh_p434_compressed_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIDH_P610_SHA256:
		r = kex_kem_sidh_p610_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIDH_P610_COMPRESSED_SHA256:
		r = kex_kem_sidh_p610_compressed_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIDH_P751_SHA256:
		r = kex_kem_sidh_p751_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIDH_P751_COMPRESSED_SHA256:
		r = kex_kem_sidh_p751_compressed_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIKE_P434_SHA256:
		r = kex_kem_sike_p434_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIKE_P434_COMPRESSED_SHA256:
		r = kex_kem_sike_p434_compressed_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIKE_P610_SHA256:
		r = kex_kem_sike_p610_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIKE_P610_COMPRESSED_SHA256:
		r = kex_kem_sike_p610_compressed_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIKE_P751_SHA256:
		r = kex_kem_sike_p751_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIKE_P751_COMPRESSED_SHA256:
		r = kex_kem_sike_p751_compressed_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SABER_LIGHTSABER_SHA256:
		r = kex_kem_saber_lightsaber_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SABER_SABER_SHA384:
		r = kex_kem_saber_saber_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SABER_FIRESABER_SHA512:
		r = kex_kem_saber_firesaber_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_KYBER_512_SHA256:
		r = kex_kem_kyber_512_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_KYBER_768_SHA384:
		r = kex_kem_kyber_768_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_KYBER_1024_SHA512:
		r = kex_kem_kyber_1024_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_KYBER_512_90S_SHA256:
		r = kex_kem_kyber_512_90s_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_KYBER_768_90S_SHA384:
		r = kex_kem_kyber_768_90s_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_KYBER_1024_90S_SHA512:
		r = kex_kem_kyber_1024_90s_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L1_CPA_SHA512:
		r = kex_kem_bike1_l1_cpa_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L1_FO_SHA512:
		r = kex_kem_bike1_l1_fo_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L3_CPA_SHA512:
		r = kex_kem_bike1_l3_cpa_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L3_FO_SHA512:
		r = kex_kem_bike1_l3_fo_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRU_HPS2048509_SHA512:
		r = kex_kem_ntru_hps2048509_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRU_HPS2048677_SHA512:
		r = kex_kem_ntru_hps2048677_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRU_HRSS701_SHA512:
		r = kex_kem_ntru_hrss701_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRU_HPS4096821_SHA512:
		r = kex_kem_ntru_hps4096821_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_348864_SHA256:
		r = kex_kem_classic_mceliece_348864_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_348864F_SHA256:
		r = kex_kem_classic_mceliece_348864f_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_460896_SHA512:
		r = kex_kem_classic_mceliece_460896_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_460896F_SHA512:
		r = kex_kem_classic_mceliece_460896f_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6688128_SHA512:
		r = kex_kem_classic_mceliece_6688128_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6688128F_SHA512:
		r = kex_kem_classic_mceliece_6688128f_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6960119_SHA512:
		r = kex_kem_classic_mceliece_6960119_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6960119F_SHA512:
		r = kex_kem_classic_mceliece_6960119f_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_8192128_SHA512:
		r = kex_kem_classic_mceliece_8192128_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_8192128F_SHA512:
		r = kex_kem_classic_mceliece_8192128f_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_HQC_128_SHA256:
		r = kex_kem_hqc_128_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_HQC_192_SHA384:
		r = kex_kem_hqc_192_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_HQC_256_SHA512:
		r = kex_kem_hqc_256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR653_SHA256:
		r = kex_kem_ntruprime_ntrulpr653_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP653_SHA256:
		r = kex_kem_ntruprime_sntrup653_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR761_SHA384:
		r = kex_kem_ntruprime_ntrulpr761_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP761_SHA384:
		r = kex_kem_ntruprime_sntrup761_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR857_SHA384:
		r = kex_kem_ntruprime_ntrulpr857_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP857_SHA384:
		r = kex_kem_ntruprime_sntrup857_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
#ifdef WITH_OPENSSL
#ifdef OPENSSL_HAS_ECC
	case KEX_KEM_OQS_DEFAULT_ECDH_NISTP256_SHA256:
		r = kex_kem_oqs_default_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_640_AES_ECDH_NISTP256_SHA256:
		r = kex_kem_frodokem_640_aes_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_976_AES_ECDH_NISTP384_SHA384:
		r = kex_kem_frodokem_976_aes_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_1344_AES_ECDH_NISTP521_SHA512:
		r = kex_kem_frodokem_1344_aes_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_640_SHAKE_ECDH_NISTP256_SHA256:
		r = kex_kem_frodokem_640_shake_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_976_SHAKE_ECDH_NISTP384_SHA384:
		r = kex_kem_frodokem_976_shake_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_FRODOKEM_1344_SHAKE_ECDH_NISTP521_SHA512:
		r = kex_kem_frodokem_1344_shake_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIDH_P434_ECDH_NISTP256_SHA256:
		r = kex_kem_sidh_p434_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIDH_P434_COMPRESSED_ECDH_NISTP256_SHA256:
		r = kex_kem_sidh_p434_compressed_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIDH_P610_ECDH_NISTP384_SHA256:
		r = kex_kem_sidh_p610_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIDH_P610_COMPRESSED_ECDH_NISTP384_SHA256:
		r = kex_kem_sidh_p610_compressed_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIDH_P751_ECDH_NISTP521_SHA256:
		r = kex_kem_sidh_p751_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIDH_P751_COMPRESSED_ECDH_NISTP521_SHA256:
		r = kex_kem_sidh_p751_compressed_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIKE_P434_ECDH_NISTP256_SHA256:
		r = kex_kem_sike_p434_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIKE_P434_COMPRESSED_ECDH_NISTP256_SHA256:
		r = kex_kem_sike_p434_compressed_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIKE_P610_ECDH_NISTP384_SHA256:
		r = kex_kem_sike_p610_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIKE_P610_COMPRESSED_ECDH_NISTP384_SHA256:
		r = kex_kem_sike_p610_compressed_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIKE_P751_ECDH_NISTP521_SHA256:
		r = kex_kem_sike_p751_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SIKE_P751_COMPRESSED_ECDH_NISTP521_SHA256:
		r = kex_kem_sike_p751_compressed_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SABER_LIGHTSABER_ECDH_NISTP256_SHA256:
		r = kex_kem_saber_lightsaber_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SABER_SABER_ECDH_NISTP384_SHA384:
		r = kex_kem_saber_saber_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_SABER_FIRESABER_ECDH_NISTP521_SHA512:
		r = kex_kem_saber_firesaber_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_KYBER_512_ECDH_NISTP256_SHA256:
		r = kex_kem_kyber_512_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_KYBER_768_ECDH_NISTP384_SHA384:
		r = kex_kem_kyber_768_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_KYBER_1024_ECDH_NISTP521_SHA512:
		r = kex_kem_kyber_1024_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_KYBER_512_90S_ECDH_NISTP256_SHA256:
		r = kex_kem_kyber_512_90s_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_KYBER_768_90S_ECDH_NISTP384_SHA384:
		r = kex_kem_kyber_768_90s_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_KYBER_1024_90S_ECDH_NISTP521_SHA512:
		r = kex_kem_kyber_1024_90s_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L1_CPA_ECDH_NISTP256_SHA512:
		r = kex_kem_bike1_l1_cpa_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L1_FO_ECDH_NISTP256_SHA512:
		r = kex_kem_bike1_l1_fo_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L3_CPA_ECDH_NISTP384_SHA512:
		r = kex_kem_bike1_l3_cpa_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_BIKE1_L3_FO_ECDH_NISTP384_SHA512:
		r = kex_kem_bike1_l3_fo_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRU_HPS2048509_ECDH_NISTP256_SHA512:
		r = kex_kem_ntru_hps2048509_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRU_HPS2048677_ECDH_NISTP384_SHA512:
		r = kex_kem_ntru_hps2048677_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRU_HRSS701_ECDH_NISTP384_SHA512:
		r = kex_kem_ntru_hrss701_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRU_HPS4096821_ECDH_NISTP521_SHA512:
		r = kex_kem_ntru_hps4096821_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_348864_ECDH_NISTP256_SHA256:
		r = kex_kem_classic_mceliece_348864_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_348864F_ECDH_NISTP256_SHA256:
		r = kex_kem_classic_mceliece_348864f_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_460896_ECDH_NISTP384_SHA512:
		r = kex_kem_classic_mceliece_460896_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_460896F_ECDH_NISTP384_SHA512:
		r = kex_kem_classic_mceliece_460896f_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6688128_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_6688128_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6688128F_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_6688128f_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6960119_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_6960119_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_6960119F_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_6960119f_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_8192128_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_8192128_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_CLASSIC_MCELIECE_8192128F_ECDH_NISTP521_SHA512:
		r = kex_kem_classic_mceliece_8192128f_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_HQC_128_ECDH_NISTP256_SHA256:
		r = kex_kem_hqc_128_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_HQC_192_ECDH_NISTP384_SHA384:
		r = kex_kem_hqc_192_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_HQC_256_ECDH_NISTP521_SHA512:
		r = kex_kem_hqc_256_ecdh_nistp521_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR653_ECDH_NISTP256_SHA256:
		r = kex_kem_ntruprime_ntrulpr653_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP653_ECDH_NISTP256_SHA256:
		r = kex_kem_ntruprime_sntrup653_ecdh_nistp256_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR761_ECDH_NISTP384_SHA384:
		r = kex_kem_ntruprime_ntrulpr761_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP761_ECDH_NISTP384_SHA384:
		r = kex_kem_ntruprime_sntrup761_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_NTRULPR857_ECDH_NISTP384_SHA384:
		r = kex_kem_ntruprime_ntrulpr857_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
	case KEX_KEM_NTRUPRIME_SNTRUP857_ECDH_NISTP384_SHA384:
		r = kex_kem_ntruprime_sntrup857_ecdh_nistp384_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		break;
#endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */
///// OQS_TEMPLATE_FRAGMENT_ADD_INIT_SWITCH_CASES_END
	default:
		r = SSH_ERR_INVALID_ARGUMENT;
		break;
	}
	if (r !=0 )
		goto out;

	/* calc H */
	if ((server_host_key_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_putb(server_host_public, server_host_key_blob)) != 0)
		goto out;
	hashlen = sizeof(hash);
	if ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_key_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		goto out;

	/* sign H */
	if ((r = kex->sign(ssh, server_host_private, server_host_public,
	     &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		goto out;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_ECDH_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_key_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);
out:
	explicit_bzero(hash, sizeof(hash));
	sshbuf_free(server_host_key_blob);
	free(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	return r;
}
