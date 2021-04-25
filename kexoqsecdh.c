/* $OpenBSD: kexoqsecdh.c,v 1.3 2019/01/21 10:40:11 djm Exp $ */
/*
 * Adapted from kexecdh.c and kexsntrup4591761x25519.c for hybrid PQC algs.
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

#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "oqs/oqs.h"

/* helper static function copied from kexecdh.c (OQS-TODO: should I expose that function instead of copying it) */
static int
kex_ecdh_dec_key_group(struct kex *kex, const struct sshbuf *ec_blob,
    EC_KEY *key, const EC_GROUP *group, struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	BIGNUM *shared_secret = NULL;
	EC_POINT *dh_pub = NULL;
	u_char *kbuf = NULL;
	size_t klen = 0;
	int r;

	*shared_secretp = NULL;

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		goto out;
	if ((dh_pub = EC_POINT_new(group)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		goto out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	if (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	if ((kbuf = malloc(klen)) == NULL ||
	    (shared_secret = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (ECDH_compute_key(kbuf, klen, dh_pub, key, NULL) != (int)klen ||
	    BN_bin2bn(kbuf, klen, shared_secret) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	if ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
		goto out;
	*shared_secretp = buf;
	buf = NULL;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	return r;
}

static int kex_kem_generic_with_ec_keypair(OQS_KEM *kem, struct kex *kex)
{
  /* the client public key to send to the server (contatenation of PQC and ecdh public keys) */
  struct sshbuf *buf = NULL;
  u_char *pqc_public_key = NULL;
  /* ecdh values */
  EC_KEY *ecdh_client_key = NULL;
  const EC_GROUP *ecdh_group;
  const EC_POINT *ecdh_public_key;
  struct sshbuf *ecdh_buf = NULL;
  int r;
  /* allocate space for PQC public key (ecdh will be concatenated later) */
  if ((buf = sshbuf_new()) == NULL)
    return SSH_ERR_ALLOC_FAIL;
  if ((r = sshbuf_reserve(buf, kem->length_public_key, &pqc_public_key)) != 0)
    goto out;

  /* generate the PQC key */
  kex->oqs_client_key_size = kem->length_secret_key;
  if ((kex->oqs_client_key = malloc(kex->oqs_client_key_size)) == NULL ||
      OQS_KEM_keypair(kem, pqc_public_key, kex->oqs_client_key) != OQS_SUCCESS) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  /* allocate space for ecdh public key (to be appended to buf later) */
  if ((ecdh_buf = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  /* generate the ecdh key, as done in kex_ecdh_keypair(...) */
  if ((ecdh_client_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  if (EC_KEY_generate_key(ecdh_client_key) != 1) {
    r = SSH_ERR_LIBCRYPTO_ERROR;
    goto out;
  }
  ecdh_group = EC_KEY_get0_group(ecdh_client_key);
  ecdh_public_key = EC_KEY_get0_public_key(ecdh_client_key);
  if ((r = sshbuf_put_ec(ecdh_buf, ecdh_public_key, ecdh_group)) != 0 ||
      (r = sshbuf_get_u32(ecdh_buf, NULL)) != 0)
    goto out;
  /* concatenate ecdh public key with the PQC one */
  if ((r = sshbuf_putb(buf, ecdh_buf)) != 0) {
    goto out;
  }

  /* store the values for decryption */
  kex->ec_client_key = ecdh_client_key;
  kex->ec_group = ecdh_group;
  ecdh_client_key = NULL; /* owned by the kex */
  kex->client_pub = buf;
  buf = NULL;
 out:
  sshbuf_free(buf);
  sshbuf_free(ecdh_buf);
  return r;
}

static int kex_kem_generic_with_ec_enc(OQS_KEM *kem,
                                struct kex *kex,
                                const struct sshbuf *client_blob,
                                struct sshbuf **server_blobp,
                                struct sshbuf **shared_secretp)
{
  /* the server's PQC KEM key and ecdh shared secret */
  struct sshbuf *buf = NULL;
  /* the server's PQC ciphertext and ecdh data to send to the client */
  struct sshbuf *server_blob = NULL;
  const u_char *client_pub;
  u_char *kem_key, *ciphertext;
  /* ecdh values */
  const EC_GROUP *ecdh_group;
  const EC_POINT *ecdh_pub_key;
  EC_KEY *ecdh_server_key = NULL;
  struct sshbuf *ecdh_client_blob = NULL;
  struct sshbuf *ecdh_server_blob = NULL;
  struct sshbuf *ecdh_shared_secret;
  u_char hash[SSH_DIGEST_MAX_LENGTH];
  int r;
  *server_blobp = NULL;
  *shared_secretp = NULL;

  /* client_blob contains both KEM and ECDH client pubkeys */
  /* is the ecdh p256 key always 65 bytes? can I check that? kexecdh.c
     doesn't check anything only check min size for ALG? */
  /* need = OQS_KEM_##ALG##_length_public_key + 65;
     if (sshbuf_len(client_blob) < OQS_KEM_##ALG##_length_public_key) { \
     r = SSH_ERR_SIGNATURE_INVALID;
     goto out;
     }*/

  /* get a pointer to the client PQC public key */
  client_pub = sshbuf_ptr(client_blob);
  /* allocate buffer for concatenation of KEM key and ECDH shared key */
  /* the buffer will be hashed and the result is the shared secret */
  if ((buf = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  if ((r = sshbuf_reserve(buf, kem->length_shared_secret, &kem_key)) != 0)
    goto out;

  /* allocate buffer for encrypted KEM key and ecdh value */
  if ((server_blob = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  if ((r = sshbuf_reserve(server_blob, kem->length_ciphertext, &ciphertext)) != 0)
    goto out;

  /* generate and encrypt KEM key with client key */
  if (OQS_KEM_encaps(kem, ciphertext, kem_key, client_pub) != OQS_SUCCESS) {
    goto out;
  }

  /* allocate buffers for ecdh data */
  if ((ecdh_server_blob = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  ecdh_client_blob = sshbuf_from(client_pub + kem->length_public_key, sshbuf_len(client_blob) - kem->length_public_key);
  /* generate ecdh key pair, store server ecdh public key after KEM ciphertext
     as done in kex_ecdh_enc(...) */
  if ((ecdh_server_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  if (EC_KEY_generate_key(ecdh_server_key) != 1) {
    r = SSH_ERR_LIBCRYPTO_ERROR;
    goto out;
  }
  ecdh_group = EC_KEY_get0_group(ecdh_server_key);
  ecdh_pub_key = EC_KEY_get0_public_key(ecdh_server_key);
  if ((r = sshbuf_put_ec(ecdh_server_blob, ecdh_pub_key, ecdh_group)) != 0 ||
      (r = sshbuf_get_u32(ecdh_server_blob, NULL)) != 0)
    goto out;

  /* concatenate ecdh server blob with the PQC one */
  if ((r = sshbuf_putb(server_blob, ecdh_server_blob)) != 0) {
    goto out;
  }

  if ((r = kex_ecdh_dec_key_group(kex, ecdh_client_blob, ecdh_server_key, ecdh_group, &ecdh_shared_secret)) != 0)
    goto out;

  /* concatenate ecdh shared secret with the PQC one */
  if ((r = sshbuf_putb(buf, ecdh_shared_secret)) != 0)
    goto out;

  /* hash concatenation of KEM key and ECDH shared key*/
  if ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, sizeof(hash))) != 0)
    goto out;

  /* string-encoded hash is resulting shared secret */
  sshbuf_reset(buf);
  if ((r = sshbuf_put_string(buf, hash, ssh_digest_bytes(kex->hash_alg))) != 0)
    goto out;

  *server_blobp = server_blob;
  *shared_secretp = buf;
  server_blob = NULL;
  buf = NULL;
 out:
  explicit_bzero(hash, sizeof(hash));
  EC_KEY_free(ecdh_server_key);
  sshbuf_free(server_blob);
  sshbuf_free(ecdh_client_blob);
  sshbuf_free(buf);
  return r;
}

static int kex_kem_generic_with_ec_dec(OQS_KEM *kem,
                                struct kex *kex,
                                const struct sshbuf *server_blob,
                                struct sshbuf **shared_secretp)
{
  /* the server's PQC KEM key and ecdh shared secret */
  struct sshbuf *buf = NULL;
  u_char *kem_key = NULL;
  const u_char *ciphertext;

  /* ecdh values */
  struct sshbuf *ecdh_shared_secret;
  struct sshbuf *ecdh_server_blob = NULL;
  u_char hash[SSH_DIGEST_MAX_LENGTH];
  int r;
  *shared_secretp = NULL;

  /* server_blob contains both KEM and ECDH server keys */
  /* is the ecdh p256 key always 65 bytes? can I check that? kexecdh.c doesn't check anything
     only check min size for ALG?
     need = OQS_KEM_##ALG##_length_ciphertext + 65;
     if (sshbuf_len(server_blob) != need) {
     r = SSH_ERR_SIGNATURE_INVALID;
     goto out;
     } */

    /* get a pointer to the server PQC ciphertext */
    ciphertext = sshbuf_ptr(server_blob);

    /* allocate buffer for concatenation of KEM key and ECDH shared key */
    /* the buffer will be hashed and the result is the shared secret */
    if ((buf = sshbuf_new()) == NULL) {
      r = SSH_ERR_ALLOC_FAIL;
      goto out;
    }
    if ((r = sshbuf_reserve(buf, kem->length_shared_secret, &kem_key)) != 0)
      goto out;
    /* decapsulate the post-quantum secret */
    if (OQS_KEM_decaps(kem, kem_key, ciphertext, kex->oqs_client_key) != OQS_SUCCESS) {
      goto out;
    }

    /* derive the ecdh shared key, using 2nd part of server_blob
       as done in kex_ecdh_dec(...) */
    ecdh_server_blob = sshbuf_from(ciphertext + kem->length_ciphertext, sshbuf_len(server_blob) - kem->length_ciphertext);

    if ((r = kex_ecdh_dec_key_group(kex, ecdh_server_blob, kex->ec_client_key,
                                    kex->ec_group, &ecdh_shared_secret)) != 0)
      goto out;
    /* concatenate ecdh shared secret with the PQC one */
    if ((r = sshbuf_putb(buf, ecdh_shared_secret)) != 0)
      goto out;

    /* hash concatenation of KEM key and ECDH shared key*/
    if ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, sizeof(hash))) != 0)
      goto out;
    sshbuf_reset(buf);
    if ((r = sshbuf_put_string(buf, hash, ssh_digest_bytes(kex->hash_alg))) != 0)
      goto out;
    *shared_secretp = buf;
    buf = NULL;

out:
    EC_KEY_free(kex->ec_client_key);
    kex->ec_client_key = NULL;
    explicit_bzero(hash, sizeof(hash));
    sshbuf_free(buf);
    sshbuf_free(ecdh_server_blob);
    return r;
}

///// OQS_TEMPLATE_FRAGMENT_DEFINE_KEX_WITH_EC_METHODS_START
/*---------------------------------------------------------------
 * OQS_DEFAULT_ECDH_NISTP256 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_oqs_default_ecdh_nistp256_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_default);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_oqs_default_ecdh_nistp256_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_default);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_oqs_default_ecdh_nistp256_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_default);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * FRODOKEM_640_AES_ECDH_NISTP256 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_frodokem_640_aes_ecdh_nistp256_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_640_aes_ecdh_nistp256_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_640_aes_ecdh_nistp256_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * FRODOKEM_976_AES_ECDH_NISTP384 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_frodokem_976_aes_ecdh_nistp384_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_976_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_976_aes_ecdh_nistp384_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_976_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_976_aes_ecdh_nistp384_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_976_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * FRODOKEM_1344_AES_ECDH_NISTP521 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_frodokem_1344_aes_ecdh_nistp521_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_1344_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_1344_aes_ecdh_nistp521_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_1344_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_1344_aes_ecdh_nistp521_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_1344_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * SIKE_P434_ECDH_NISTP256 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_sike_p434_ecdh_nistp256_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sike_p434_ecdh_nistp256_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sike_p434_ecdh_nistp256_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_ec_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
///// OQS_TEMPLATE_FRAGMENT_DEFINE_KEX_WITH_EC_METHODS_END

#endif /* defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC) */
