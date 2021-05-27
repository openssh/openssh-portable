/* $OpenBSD: kexoqs.c,v 1.3 2019/01/21 10:40:11 djm Exp $ */
/*
 * Adapted from kexsntrup4591761x25519.c for OQS algs.
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

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "oqs/oqs.h"

static int kex_kem_generic_keypair(OQS_KEM *kem, struct kex *kex)
{
  struct sshbuf *buf = NULL;
  u_char *cp = NULL;
  int r;
  if ((buf = sshbuf_new()) == NULL)
    return SSH_ERR_ALLOC_FAIL;
  if ((r = sshbuf_reserve(buf, kem->length_public_key, &cp)) != 0) \
    goto out;
  kex->oqs_client_key_size = kem->length_secret_key;
  if ((kex->oqs_client_key = malloc(kex->oqs_client_key_size)) == NULL ||
      OQS_KEM_keypair(kem, cp, kex->oqs_client_key) != OQS_SUCCESS) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  kex->client_pub = buf;
  buf = NULL;
 out:
  sshbuf_free(buf);
  return r;
}

static int kex_kem_generic_enc(OQS_KEM *kem, struct kex *kex,
                               const struct sshbuf *client_blob,
                               struct sshbuf **server_blobp,
                               struct sshbuf **shared_secretp)
{
  struct sshbuf *server_blob = NULL;
  struct sshbuf *buf = NULL;
  const u_char *client_pub;
  u_char *kem_key, *ciphertext;
  int r;
  *server_blobp = NULL;
  *shared_secretp = NULL;
  if (sshbuf_len(client_blob) != kem->length_public_key) {
    r = SSH_ERR_SIGNATURE_INVALID;
    goto out;
  }
  client_pub = sshbuf_ptr(client_blob);
  if ((buf = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  if ((r = sshbuf_reserve(buf, kem->length_shared_secret, &kem_key)) != 0)
    goto out;
  /* allocate space for encrypted KEM key */
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
  *server_blobp = server_blob;
  *shared_secretp = buf;
  server_blob = NULL;
  buf = NULL;
 out:
  sshbuf_free(server_blob);
  sshbuf_free(buf);
  return r;
}

static int kex_kem_generic_dec(OQS_KEM *kem,
                               struct kex *kex,
                               const struct sshbuf *server_blob,
                               struct sshbuf **shared_secretp)
{
  struct sshbuf *buf = NULL;
  u_char *kem_key = NULL;
  const u_char *ciphertext;
  int r;
  *shared_secretp = NULL;
  if (sshbuf_len(server_blob) != kem->length_ciphertext) {
    r = SSH_ERR_SIGNATURE_INVALID;
    goto out;
  }
  ciphertext = sshbuf_ptr(server_blob);
  /* #ifdef DEBUG_KEXECDH
    dump_digest("server cipher text:", ciphertext, OQS_KEM_##ALG##_length_ciphertext);
    #endif */
  /* decrypt the KEM key */
  if ((buf = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  if ((r = sshbuf_reserve(buf, kem->length_shared_secret, &kem_key)) != 0)
    goto out;
  if (OQS_KEM_decaps(kem, kem_key, ciphertext, kex->oqs_client_key) != OQS_SUCCESS) {
    goto out;
  }
  *shared_secretp = buf;
  buf = NULL;
 out:
  sshbuf_free(buf);
  return r;
}

///// OQS_TEMPLATE_FRAGMENT_DEFINE_KEX_METHODS_START
/*---------------------------------------------------
 * OQS_DEFAULT METHODS
 *---------------------------------------------------
 */
int kex_kem_oqs_default_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_default);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_oqs_default_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_default);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_oqs_default_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_default);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * FRODOKEM_640_AES METHODS
 *---------------------------------------------------
 */
int kex_kem_frodokem_640_aes_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_frodokem_640_aes_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_640_aes_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * FRODOKEM_976_AES METHODS
 *---------------------------------------------------
 */
int kex_kem_frodokem_976_aes_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_976_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_frodokem_976_aes_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_976_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_976_aes_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_976_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * FRODOKEM_1344_AES METHODS
 *---------------------------------------------------
 */
int kex_kem_frodokem_1344_aes_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_1344_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_frodokem_1344_aes_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_1344_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_1344_aes_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_1344_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * FRODOKEM_640_SHAKE METHODS
 *---------------------------------------------------
 */
int kex_kem_frodokem_640_shake_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_shake);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_frodokem_640_shake_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_shake);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_640_shake_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_shake);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * FRODOKEM_976_SHAKE METHODS
 *---------------------------------------------------
 */
int kex_kem_frodokem_976_shake_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_976_shake);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_frodokem_976_shake_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_976_shake);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_976_shake_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_976_shake);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * FRODOKEM_1344_SHAKE METHODS
 *---------------------------------------------------
 */
int kex_kem_frodokem_1344_shake_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_1344_shake);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_frodokem_1344_shake_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_1344_shake);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_1344_shake_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_1344_shake);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIDH_P434 METHODS
 *---------------------------------------------------
 */
int kex_kem_sidh_p434_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p434);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sidh_p434_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p434);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sidh_p434_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p434);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIDH_P434_COMPRESSED METHODS
 *---------------------------------------------------
 */
int kex_kem_sidh_p434_compressed_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p434_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sidh_p434_compressed_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p434_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sidh_p434_compressed_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p434_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIDH_P610 METHODS
 *---------------------------------------------------
 */
int kex_kem_sidh_p610_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p610);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sidh_p610_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p610);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sidh_p610_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p610);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIDH_P610_COMPRESSED METHODS
 *---------------------------------------------------
 */
int kex_kem_sidh_p610_compressed_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p610_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sidh_p610_compressed_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p610_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sidh_p610_compressed_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p610_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIDH_P751 METHODS
 *---------------------------------------------------
 */
int kex_kem_sidh_p751_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p751);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sidh_p751_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p751);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sidh_p751_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p751);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIDH_P751_COMPRESSED METHODS
 *---------------------------------------------------
 */
int kex_kem_sidh_p751_compressed_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p751_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sidh_p751_compressed_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p751_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sidh_p751_compressed_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sidh_p751_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIKE_P434 METHODS
 *---------------------------------------------------
 */
int kex_kem_sike_p434_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sike_p434_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sike_p434_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIKE_P434_COMPRESSED METHODS
 *---------------------------------------------------
 */
int kex_kem_sike_p434_compressed_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sike_p434_compressed_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sike_p434_compressed_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIKE_P610 METHODS
 *---------------------------------------------------
 */
int kex_kem_sike_p610_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p610);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sike_p610_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p610);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sike_p610_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p610);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIKE_P610_COMPRESSED METHODS
 *---------------------------------------------------
 */
int kex_kem_sike_p610_compressed_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p610_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sike_p610_compressed_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p610_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sike_p610_compressed_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p610_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIKE_P751 METHODS
 *---------------------------------------------------
 */
int kex_kem_sike_p751_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p751);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sike_p751_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p751);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sike_p751_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p751);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIKE_P751_COMPRESSED METHODS
 *---------------------------------------------------
 */
int kex_kem_sike_p751_compressed_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p751_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sike_p751_compressed_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p751_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sike_p751_compressed_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p751_compressed);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SABER_LIGHTSABER METHODS
 *---------------------------------------------------
 */
int kex_kem_saber_lightsaber_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_saber_lightsaber);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_saber_lightsaber_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_saber_lightsaber);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_saber_lightsaber_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_saber_lightsaber);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SABER_SABER METHODS
 *---------------------------------------------------
 */
int kex_kem_saber_saber_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_saber_saber);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_saber_saber_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_saber_saber);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_saber_saber_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_saber_saber);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SABER_FIRESABER METHODS
 *---------------------------------------------------
 */
int kex_kem_saber_firesaber_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_saber_firesaber);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_saber_firesaber_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_saber_firesaber);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_saber_firesaber_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_saber_firesaber);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * KYBER_512 METHODS
 *---------------------------------------------------
 */
int kex_kem_kyber_512_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_kyber_512_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_kyber_512_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * KYBER_768 METHODS
 *---------------------------------------------------
 */
int kex_kem_kyber_768_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_kyber_768_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_kyber_768_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * KYBER_1024 METHODS
 *---------------------------------------------------
 */
int kex_kem_kyber_1024_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_kyber_1024_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_kyber_1024_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * KYBER_512_90S METHODS
 *---------------------------------------------------
 */
int kex_kem_kyber_512_90s_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512_90s);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_kyber_512_90s_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512_90s);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_kyber_512_90s_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512_90s);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * KYBER_768_90S METHODS
 *---------------------------------------------------
 */
int kex_kem_kyber_768_90s_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768_90s);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_kyber_768_90s_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768_90s);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_kyber_768_90s_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768_90s);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * KYBER_1024_90S METHODS
 *---------------------------------------------------
 */
int kex_kem_kyber_1024_90s_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024_90s);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_kyber_1024_90s_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024_90s);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_kyber_1024_90s_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024_90s);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * BIKE1_L1_CPA METHODS
 *---------------------------------------------------
 */
int kex_kem_bike1_l1_cpa_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike1_l1_cpa);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_bike1_l1_cpa_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike1_l1_cpa);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_bike1_l1_cpa_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike1_l1_cpa);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * BIKE1_L1_FO METHODS
 *---------------------------------------------------
 */
int kex_kem_bike1_l1_fo_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike1_l1_fo);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_bike1_l1_fo_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike1_l1_fo);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_bike1_l1_fo_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike1_l1_fo);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * BIKE1_L3_CPA METHODS
 *---------------------------------------------------
 */
int kex_kem_bike1_l3_cpa_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike1_l3_cpa);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_bike1_l3_cpa_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike1_l3_cpa);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_bike1_l3_cpa_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike1_l3_cpa);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * BIKE1_L3_FO METHODS
 *---------------------------------------------------
 */
int kex_kem_bike1_l3_fo_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike1_l3_fo);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_bike1_l3_fo_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike1_l3_fo);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_bike1_l3_fo_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike1_l3_fo);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * NTRU_HPS2048509 METHODS
 *---------------------------------------------------
 */
int kex_kem_ntru_hps2048509_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps2048509);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_ntru_hps2048509_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps2048509);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ntru_hps2048509_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps2048509);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * NTRU_HPS2048677 METHODS
 *---------------------------------------------------
 */
int kex_kem_ntru_hps2048677_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps2048677);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_ntru_hps2048677_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps2048677);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ntru_hps2048677_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps2048677);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * NTRU_HRSS701 METHODS
 *---------------------------------------------------
 */
int kex_kem_ntru_hrss701_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hrss701);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_ntru_hrss701_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hrss701);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ntru_hrss701_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hrss701);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * NTRU_HPS4096821 METHODS
 *---------------------------------------------------
 */
int kex_kem_ntru_hps4096821_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps4096821);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_ntru_hps4096821_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps4096821);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ntru_hps4096821_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps4096821);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * CLASSIC_MCELIECE_348864 METHODS
 *---------------------------------------------------
 */
int kex_kem_classic_mceliece_348864_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_classic_mceliece_348864_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_348864_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * CLASSIC_MCELIECE_348864F METHODS
 *---------------------------------------------------
 */
int kex_kem_classic_mceliece_348864f_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_classic_mceliece_348864f_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_348864f_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * CLASSIC_MCELIECE_460896 METHODS
 *---------------------------------------------------
 */
int kex_kem_classic_mceliece_460896_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_460896);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_classic_mceliece_460896_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_460896);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_460896_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_460896);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * CLASSIC_MCELIECE_460896F METHODS
 *---------------------------------------------------
 */
int kex_kem_classic_mceliece_460896f_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_460896f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_classic_mceliece_460896f_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_460896f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_460896f_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_460896f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * CLASSIC_MCELIECE_6688128 METHODS
 *---------------------------------------------------
 */
int kex_kem_classic_mceliece_6688128_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_6688128);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_classic_mceliece_6688128_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_6688128);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_6688128_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_6688128);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * CLASSIC_MCELIECE_6688128F METHODS
 *---------------------------------------------------
 */
int kex_kem_classic_mceliece_6688128f_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_6688128f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_classic_mceliece_6688128f_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_6688128f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_6688128f_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_6688128f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * CLASSIC_MCELIECE_6960119 METHODS
 *---------------------------------------------------
 */
int kex_kem_classic_mceliece_6960119_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_6960119);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_classic_mceliece_6960119_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_6960119);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_6960119_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_6960119);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * CLASSIC_MCELIECE_6960119F METHODS
 *---------------------------------------------------
 */
int kex_kem_classic_mceliece_6960119f_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_6960119f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_classic_mceliece_6960119f_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_6960119f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_6960119f_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_6960119f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * CLASSIC_MCELIECE_8192128 METHODS
 *---------------------------------------------------
 */
int kex_kem_classic_mceliece_8192128_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_8192128);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_classic_mceliece_8192128_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_8192128);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_8192128_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_8192128);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * CLASSIC_MCELIECE_8192128F METHODS
 *---------------------------------------------------
 */
int kex_kem_classic_mceliece_8192128f_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_8192128f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_classic_mceliece_8192128f_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_8192128f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_8192128f_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_8192128f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * HQC_128 METHODS
 *---------------------------------------------------
 */
int kex_kem_hqc_128_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_128);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_hqc_128_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_128);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_hqc_128_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_128);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * HQC_192 METHODS
 *---------------------------------------------------
 */
int kex_kem_hqc_192_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_192);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_hqc_192_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_192);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_hqc_192_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_192);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * HQC_256 METHODS
 *---------------------------------------------------
 */
int kex_kem_hqc_256_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_256);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_hqc_256_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_256);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_hqc_256_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_256);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * NTRUPRIME_NTRULPR653 METHODS
 *---------------------------------------------------
 */
int kex_kem_ntruprime_ntrulpr653_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_ntrulpr653);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_ntruprime_ntrulpr653_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_ntrulpr653);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ntruprime_ntrulpr653_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_ntrulpr653);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * NTRUPRIME_SNTRUP653 METHODS
 *---------------------------------------------------
 */
int kex_kem_ntruprime_sntrup653_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup653);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_ntruprime_sntrup653_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup653);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ntruprime_sntrup653_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup653);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * NTRUPRIME_NTRULPR761 METHODS
 *---------------------------------------------------
 */
int kex_kem_ntruprime_ntrulpr761_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_ntrulpr761);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_ntruprime_ntrulpr761_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_ntrulpr761);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ntruprime_ntrulpr761_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_ntrulpr761);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * NTRUPRIME_SNTRUP761 METHODS
 *---------------------------------------------------
 */
int kex_kem_ntruprime_sntrup761_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup761);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_ntruprime_sntrup761_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup761);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ntruprime_sntrup761_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup761);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * NTRUPRIME_NTRULPR857 METHODS
 *---------------------------------------------------
 */
int kex_kem_ntruprime_ntrulpr857_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_ntrulpr857);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_ntruprime_ntrulpr857_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_ntrulpr857);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ntruprime_ntrulpr857_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_ntrulpr857);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * NTRUPRIME_SNTRUP857 METHODS
 *---------------------------------------------------
 */
int kex_kem_ntruprime_sntrup857_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup857);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_ntruprime_sntrup857_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup857);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ntruprime_sntrup857_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup857);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
///// OQS_TEMPLATE_FRAGMENT_DEFINE_KEX_METHODS_END
