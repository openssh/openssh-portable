/*
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

#ifdef __s390x__
#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)

#include "ssh-ibm-protk-utils.h"

#define ED25519_KEY_SIZE 256
#define ED25519_SIG_SIZE 512

extern struct sshkey_impl_funcs sshkey_ed25519_funcs;

/* PROTOTYPES */

static int
ssh_ed25519_ibm_protk_sign(struct sshkey *key, u_char **sigp, size_t *lenp,
			   const u_char *data, size_t dlen, const char *alg,
			   const char *sk_provider, const char *sk_pin,
			   u_int compat);

static int
ssh_ed25519_ibm_protk_verify(const struct sshkey *key, const u_char *sig,
			     size_t siglen, const u_char *data, size_t dlen,
			     const char *alg, u_int compat,
			     struct sshkey_sig_details **detailsp);

static u_int
ssh_ed25519_ibm_protk_size(const struct sshkey *key);

/* DEFINITIONS */

static void
ssh_ed25519_ibm_protk_cleanup(struct sshkey *k)
{
	freezero(k->protk, (ED25519_KEY_SIZE / 8));
	k->protk = NULL;

	freezero(k->wkvp, IBM_PROTK_AES_WK_VP_SIZE);
	k->wkvp = NULL;
}

static u_int
ssh_ed25519_ibm_protk_size(const struct sshkey *key)
{
	return ED25519_KEY_SIZE;
}

static int
ssh_ed25519_ibm_protk_copy_private(const struct sshkey *src, struct sshkey **dest)
{
	if (!src || !dest || src->type != KEY_ED25519_IBM_PROTK)
		return SSH_ERR_INVALID_ARGUMENT;

	*dest = (struct sshkey *) malloc(sizeof(struct sshkey));
	if (*dest == NULL)
		return SSH_ERR_ALLOC_FAIL;

	memcpy(*dest, src, sizeof(struct sshkey));

	return SSH_ERR_SUCCESS;
}

static int
ssh_ed25519_ibm_protk_equal(const struct sshkey *a, const struct sshkey *b)
{
	const u_char *data = "Hello OpenSSH World!";
	const struct sshkey *pub = NULL;
	size_t data_len = strlen(data);
	struct sshkey *prv = NULL;
	size_t sig_len;
	u_char *sig;
	int r = 0; /* Failure */

	if (a->type == KEY_ED25519_IBM_PROTK) {
		if ((r = ssh_ed25519_ibm_protk_copy_private(a, &prv)) != SSH_ERR_SUCCESS)
		return r;
	}
	else if (a->type == KEY_ED25519)
		pub = a;

	if (b->type == KEY_ED25519_IBM_PROTK && prv == NULL) {
		if ((r = ssh_ed25519_ibm_protk_copy_private(b, &prv)) != SSH_ERR_SUCCESS)
			goto out;
	} else if (b->type == KEY_ED25519_IBM_PROTK)
		goto out;
	else if (b->type == KEY_ED25519)
		pub = b;

	if (!prv || !pub)
		goto out;

	if (!pub->ed25519_pk || !prv->wkvp || !prv->protk)
		goto out;

	if ((r = ssh_ed25519_ibm_protk_sign(prv, &sig, &sig_len, data, data_len,
					    NULL, NULL, NULL, 0)) < 0)
		goto out;

	if ((r = ssh_ed25519_ibm_protk_verify(pub, sig, sig_len, data, data_len,
					      NULL, 0, NULL)) < 0)
		goto out;

	r = 1; /* Success */

out:
	if (prv)
		free(prv);
	if (sig)
		free(sig);
	return 1;
}

static int
ssh_ed25519_ibm_protk_serialize_public(const struct sshkey *key,
				       struct sshbuf *b,
				       enum sshkey_serialize_rep opts)
{
	return sshkey_ed25519_funcs.serialize_public(key, b, opts);
}

static int
ssh_ed25519_ibm_protk_deserialize_public(const char *ktype, struct sshbuf *b,
					 struct sshkey *key)
{
	return sshkey_ed25519_funcs.deserialize_public(ktype, b, key);
}

static int
ssh_ed25519_ibm_protk_serialize_private(const struct sshkey *key,
					struct sshbuf *b,
					enum sshkey_serialize_rep opts)
{
	int r;

	if ((r = sshbuf_put_string(b, key->protk,
				   ssh_ed25519_ibm_protk_size(key) / 8)) < 0)
		return r;
	if ((r = sshbuf_put_string(b, key->wkvp,
				   IBM_PROTK_AES_WK_VP_SIZE)) < 0)
		return r;

	return 0;
}

static int
ssh_ed25519_ibm_protk_deserialize_private(const char *ktype, struct sshbuf *b,
					  struct sshkey *key)
{
	u_char *ptr = NULL;
	size_t len = 0;
	int r = 0; /* Success */

	if ((r = sshbuf_get_string(b, &ptr, &len)) < 0)
		return r;

	if (!ptr || len != ssh_ed25519_ibm_protk_size(key) / 8) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	key->protk = ptr;
	ptr = NULL;

	if ((r = sshbuf_get_string(b, &ptr, &len)) < 0)
		return r;

	if (!ptr || len != IBM_PROTK_AES_WK_VP_SIZE) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	key->wkvp = ptr;
	ptr = NULL;

out:
	if (ptr)
		free(ptr);
	return r;
}

static int ed25519_sign_enc_cpacf(const uint8_t *protkey,
				  const uint8_t *wkvp, const uint8_t *hash,
				  int hashlen, u_char *sig)
{
	const struct kdsa_entry_s *ke;
	uint8_t param[4096];
	int off, rc;

	if (sig == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	ke = find_kdsa_entry(KEY_ED25519, 0);
	if (!ke)
		return SSH_ERR_INTERNAL_ERROR;
	off = ke->fsize - ke->d_size;

	memset(param, 0, sizeof(param));

	/*
	 * priv key d - protected key, so only encrypted key part
	 * we assume this prot key has fsize not d_size
	 */
	memcpy(param + 2 * ke->fsize, protkey, ke->fsize);

	/* the AES WK VP part for this prot key needs to go here: */
	memcpy(param + 3 * ke->fsize, wkvp, IBM_PROTK_AES_WK_VP_SIZE);

	/* KDSA instruction*/
	rc = s390_kdsa(ke->sign_enc_fc, param, hash, hashlen);

	/* signature r and s */
	if (rc == 0) {
		memcpy(sig + off, param + off, ke->d_size);
		memcpy(sig + ke->fsize + off, param + ke->fsize + off,
		       ke->d_size);
	} else {
		rc = SSH_ERR_NEED_REKEY;
	}

	return rc;
}

static int
ssh_ed25519_ibm_protk_sign(struct sshkey *key, u_char **sigp, size_t *lenp,
			   const u_char *data, size_t dlen, const char *alg,
			   const char *sk_provider, const char *sk_pin,
			   u_int compat)
{
	const size_t sig_size = ED25519_SIG_SIZE / 8;
	int len = 0, ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *bb = NULL;
	u_char *sig_flip = NULL;
	u_char *sig = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->wkvp == NULL ||
	    sshkey_type_plain(key->type) != KEY_ED25519)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((sig = malloc(sig_size)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* BEGIN PKEY PART */
	ret = ed25519_sign_enc_cpacf(key->protk, key->wkvp, data, dlen, sig);
	if (ret != 0)
		goto out;

	if ((sig_flip = malloc(sig_size)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/*
	 * As defined in RFC8032 EdDSA expects integers encoded in little-
	 * endian format. IBMs KDSA instruction assumes big-endian format for
	 * output integers R and S.
	 */
	for (unsigned int i = 0; i < (sig_size / 2); i++)
		sig_flip[i] = sig[((sig_size / 2) - 1) - i];
	for (unsigned int i = 0; i < (sig_size / 2); i++)
		sig_flip[(sig_size / 2) + i] = sig[(sig_size - 1) - i];
	/* END PKEY PART */

	if ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_string(b, sig_flip, sig_size)) != 0)
		goto out;

	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;

 out:
	freezero(sig, sig_size);
	freezero(sig_flip, sig_size);
	sshbuf_free(b);
	sshbuf_free(bb);
	return ret;
}

static int
ssh_ed25519_ibm_protk_verify(const struct sshkey *key, const u_char *sig,
			     size_t siglen, const u_char *data, size_t dlen,
			     const char *alg, u_int compat,
			     struct sshkey_sig_details **detailsp)
{
	return sshkey_ed25519_funcs.verify(key, sig, siglen, data, dlen, alg,
					   compat, detailsp);
}

static const struct sshkey_impl_funcs sshkey_ibm_protkey_ed25519_funcs = {
	/* .size = */		ssh_ed25519_ibm_protk_size,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_ed25519_ibm_protk_cleanup,
	/* .equal = */		ssh_ed25519_ibm_protk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_ibm_protk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_ibm_protk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_ibm_protk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_ibm_protk_deserialize_private,
	/* .generate = */	NULL,
	/* .copy_public = */	NULL,
	/* .sign = */		ssh_ed25519_ibm_protk_sign,
	/* .verify = */		ssh_ed25519_ibm_protk_verify,
};

const struct sshkey_impl sshkey_ibm_protk_ed25519_impl = {
	/* .name = */		"ibm-protk-ed25519",
	/* .shortname = */	"ED25519-IBM-PROTK",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ED25519_IBM_PROTK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ibm_protkey_ed25519_funcs,
};
#endif /* WITH_OPENSSL && OPENSSL_HAS_ECC */
#endif /* s390x Architecture */
