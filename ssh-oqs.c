/* $OpenBSD: ssh-oqs.c,v 1.8 2020/02/26 13:40:09 jsg Exp $ */
/*
 * Adapted from ssh-ed25519.c for OQS and hybrid algs.
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

#include "includes.h"

#include <sys/types.h>
#include <limits.h>

#include "crypto_api.h"

#include <string.h>
#include <stdarg.h>

#include "log.h"
#include "sshbuf.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "ssherr.h"
#include "ssh.h"

#include "oqs/oqs.h"

static int ssh_generic_sign(OQS_SIG *oqs_sig,
                            const char *alg_pretty_name,
                            const struct sshkey *key,
                            u_char **sigp,
                            size_t *lenp,
                            const u_char *data,
                            size_t datalen,
                            u_int compat)
{
  u_char *sig = NULL;
  size_t slen = 0, len;
  int r;
  struct sshbuf *b = NULL;
  struct sshbuf *ssh_algname = NULL;
  char *ssh_algname_str = NULL;

  if (lenp != NULL)
    *lenp = 0;

  if (sigp != NULL)
    *sigp = NULL;

  if (key == NULL || key->oqs_sk == NULL)
    return SSH_ERR_INVALID_ARGUMENT;

  slen = oqs_sig->length_signature;
  if ((sig = malloc(slen)) == NULL)
    return SSH_ERR_ALLOC_FAIL;

  if (OQS_SIG_sign(oqs_sig, sig, &slen, data, datalen, key->oqs_sk) != OQS_SUCCESS) {
    r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
    goto out;
  }

  /* encode signature */
  if ((b = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  if ((ssh_algname = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  if ((r = sshbuf_putf(ssh_algname, "%s-%s", "ssh", alg_pretty_name)) != 0 ||
      (ssh_algname_str = sshbuf_dup_string(ssh_algname)) == NULL) {
      goto out;
  }

  if ((r = sshbuf_put_cstring(b, ssh_algname_str)) != 0 ||
      (r = sshbuf_put_string(b, sig, slen)) != 0)
    goto out;

  len = sshbuf_len(b);
  if (sigp != NULL) {
    if ((*sigp = malloc(len)) == NULL) {
      r = SSH_ERR_ALLOC_FAIL;
      goto out;
    }
    memcpy(*sigp, sshbuf_ptr(b), len);
  }
  if (lenp != NULL)
    *lenp = len;

  /* success */
  r = 0;

out:
  sshbuf_free(b);
  sshbuf_free(ssh_algname);
  free(ssh_algname_str);
  if (sig != NULL)
    freezero(sig, slen);
  return r;
}

static int ssh_generic_verify(OQS_SIG *oqs_sig,
                              const char *alg_pretty_name,
                              const struct sshkey *key,
                              const u_char *signature,
                              size_t signaturelen,
                              const u_char *data,
                              size_t datalen,
                              u_int compat)
{
  struct sshbuf *b = NULL;
  char *algname = NULL;
  struct sshbuf *algname_expected = NULL;
  char *algname_expected_str = NULL;
  const u_char *sigblob;
  size_t slen;
  int r;

  if (key == NULL ||
      key->oqs_pk == NULL ||
      signature == NULL || signaturelen == 0)
    return SSH_ERR_INVALID_ARGUMENT;

  if ((b = sshbuf_from(signature, signaturelen)) == NULL)
    return SSH_ERR_ALLOC_FAIL;

  if ((r = sshbuf_get_cstring(b, &algname, NULL)) != 0 ||
      (r = sshbuf_get_string_direct(b, &sigblob, &slen)) != 0)
    goto out;

  if ((algname_expected = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  if ((r = sshbuf_putf(algname_expected, "%s-%s", "ssh", alg_pretty_name)) != 0 ||
      (algname_expected_str = sshbuf_dup_string(algname_expected)) == NULL) {
      goto out;
  }

  if (strcmp(algname, algname_expected_str) != 0) {
    r = SSH_ERR_KEY_TYPE_MISMATCH;
    goto out;
  }

  if (sshbuf_len(b) != 0) {
    r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
    goto out;
  }

  if (slen > oqs_sig->length_signature) {
    r = SSH_ERR_INVALID_FORMAT;
    goto out;
  }

  if (OQS_SIG_verify(oqs_sig, data, datalen, sigblob, slen, key->oqs_pk) != OQS_SUCCESS) {
    r = SSH_ERR_SIGNATURE_INVALID;
    goto out;
  }
  /* success */
  r = 0;

out:
  sshbuf_free(b);
  sshbuf_free(algname_expected);
  free(algname_expected_str);
  return r;
}

///// OQS_TEMPLATE_FRAGMENT_DEFINE_SIG_FUNCTIONS_START
/*---------------------------------------------------
 * FALCON_512 METHODS
 *---------------------------------------------------
 */
int ssh_falcon512_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "falcon512", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
int ssh_falcon512_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "falcon512", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
/*---------------------------------------------------
 * FALCON_1024 METHODS
 *---------------------------------------------------
 */
int ssh_falcon1024_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "falcon1024", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
int ssh_falcon1024_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "falcon1024", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
/*---------------------------------------------------
 * DILITHIUM_2 METHODS
 *---------------------------------------------------
 */
int ssh_dilithium2_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "dilithium2", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
int ssh_dilithium2_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "dilithium2", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
/*---------------------------------------------------
 * DILITHIUM_3 METHODS
 *---------------------------------------------------
 */
int ssh_dilithium3_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "dilithium3", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
int ssh_dilithium3_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "dilithium3", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
/*---------------------------------------------------
 * DILITHIUM_5 METHODS
 *---------------------------------------------------
 */
int ssh_dilithium5_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "dilithium5", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
int ssh_dilithium5_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "dilithium5", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
/*---------------------------------------------------
 * SPHINCS_HARAKA_128F_SIMPLE METHODS
 *---------------------------------------------------
 */
int ssh_sphincsharaka128fsimple_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_haraka_128f_simple);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "sphincsharaka128fsimple", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
int ssh_sphincsharaka128fsimple_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_haraka_128f_simple);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "sphincsharaka128fsimple", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
/*---------------------------------------------------
 * SPHINCS_SHA256_128F_SIMPLE METHODS
 *---------------------------------------------------
 */
int ssh_sphincssha256128fsimple_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha256_128f_simple);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "sphincssha256128fsimple", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
int ssh_sphincssha256128fsimple_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha256_128f_simple);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "sphincssha256128fsimple", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
/*---------------------------------------------------
 * SPHINCS_SHA256_192S_ROBUST METHODS
 *---------------------------------------------------
 */
int ssh_sphincssha256192srobust_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha256_192s_robust);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "sphincssha256192srobust", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
int ssh_sphincssha256192srobust_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha256_192s_robust);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "sphincssha256192srobust", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
/*---------------------------------------------------
 * SPHINCS_SHA256_256F_SIMPLE METHODS
 *---------------------------------------------------
 */
int ssh_sphincssha256256fsimple_sign(const struct sshkey *key,
                     u_char **sigp,
                     size_t *lenp,
                     const u_char *data,
                     size_t datalen,
                     u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha256_256f_simple);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_sign(sig, "sphincssha256256fsimple", key, sigp, lenp, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
int ssh_sphincssha256256fsimple_verify(const struct sshkey *key,
                       const u_char *signature,
                       size_t signaturelen,
                       const u_char *data,
                       size_t datalen,
                       u_int compat)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha256_256f_simple);
    if (sig == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = ssh_generic_verify(sig, "sphincssha256256fsimple", key, signature, signaturelen, data, datalen, compat);
    OQS_SIG_free(sig);
    return r;
}
///// OQS_TEMPLATE_FRAGMENT_DEFINE_SIG_FUNCTIONS_END
