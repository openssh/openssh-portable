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
#include <sys/random.h>

extern struct sshkey_impl_funcs sshkey_ecdsa_funcs;

/* PROTOTYPES */

static int
ssh_ecdsa_ibm_protk_sign(struct sshkey *key, u_char **sigp, size_t *lenp,
			 const u_char *data, size_t dlen, const char *alg,
			 const char *sk_provider, const char *sk_pin,
			 u_int compat);

static int
ssh_ecdsa_ibm_protk_verify(const struct sshkey *key, const u_char *sig,
			   size_t siglen, const u_char *data, size_t dlen,
			   const char *alg, u_int compat,
			   struct sshkey_sig_details **detailsp);

static u_int
ssh_ecdsa_ibm_protk_size(const struct sshkey *key);

/* DEFINITIONS */

static void
ssh_ecdsa_ibm_protk_cleanup(struct sshkey *k)
{
	freezero(k->protk, (sshkey_curve_nid_to_bits(k->ecdsa_nid) / 8));
	k->protk = NULL;

	freezero(k->wkvp, IBM_PROTK_AES_WK_VP_SIZE);
	k->wkvp = NULL;
}

static u_int
ssh_ecdsa_ibm_protk_size(const struct sshkey *key)
{
	return sshkey_curve_nid_to_bits(key->ecdsa_nid);
}

static int
ssh_ecdsa_ibm_protk_copy_private(const struct sshkey *src, struct sshkey **dest)
{
	if (!src || !dest || src->type != KEY_ECDSA_IBM_PROTK)
		return SSH_ERR_INVALID_ARGUMENT;

	*dest = (struct sshkey *) malloc(sizeof(struct sshkey));
	if (*dest == NULL)
		return SSH_ERR_ALLOC_FAIL;

	memcpy(*dest, src, sizeof(struct sshkey));

	return SSH_ERR_SUCCESS;
}

static int
ssh_ecdsa_ibm_protk_equal(const struct sshkey *a, const struct sshkey *b)
{
	const u_char *data = "Hello OpenSSH World!";
	const struct sshkey *pub = NULL;
	size_t data_len = strlen(data);
	struct sshkey *prv = NULL;
	size_t sig_len;
	u_char *sig;
	int r = 0; /* Failure */

	if (a->type == KEY_ECDSA_IBM_PROTK) {
		if ((r = ssh_ecdsa_ibm_protk_copy_private(a, &prv)) != SSH_ERR_SUCCESS)
			return r;
	}
	else if (a->type == KEY_ECDSA)
		pub = a;

	if (b->type == KEY_ECDSA_IBM_PROTK && prv == NULL) {
		if ((r = ssh_ecdsa_ibm_protk_copy_private(b, &prv)) != SSH_ERR_SUCCESS)
			goto out;
	} else if (b->type == KEY_ECDSA_IBM_PROTK)
		goto out;
	else if (b->type == KEY_ECDSA)
		pub = b;

	if (!prv || !pub)
		goto out;

	if (!pub->pkey || !prv->wkvp || !prv->protk)
		goto out;

	if ((r = ssh_ecdsa_ibm_protk_sign(prv, &sig, &sig_len, data, data_len,
					  NULL, NULL, NULL, 0)) < 0)
		goto out;

	if ((r = ssh_ecdsa_ibm_protk_verify(pub, sig, sig_len, data, data_len,
					    NULL, 0, NULL)) < 0)
		goto out;

	r = 1; /* Success */

out:
	if (prv)
		free(prv);
	if (sig)
		free(sig);
	return r;
}

static int
ssh_ecdsa_ibm_protk_serialize_public(const struct sshkey *key, struct sshbuf *b,
				     enum sshkey_serialize_rep opts)
{
	return sshkey_ecdsa_funcs.serialize_public(key, b, opts);
}

static int
ssh_ecdsa_ibm_protk_deserialize_public(const char *ktype, struct sshbuf *b,
				       struct sshkey *key)
{
	return sshkey_ecdsa_funcs.deserialize_public(ktype, b, key);
}

static int
ssh_ecdsa_ibm_protk_serialize_private(const struct sshkey *key,
				      struct sshbuf *b,
				      enum sshkey_serialize_rep opts)
{
	int r;

	if ((r = sshbuf_put_string(b, key->protk,
				   ssh_ecdsa_ibm_protk_size(key))) < 0)
		return r;
	if ((r = sshbuf_put_string(b, key->wkvp, IBM_PROTK_AES_WK_VP_SIZE)) < 0)
		return r;

	return 0;
}

static int
ssh_ecdsa_ibm_protk_deserialize_private(const char *ktype, struct sshbuf *b,
					struct sshkey *key)
{
	u_char *ptr = NULL;
	size_t len = 0;
	int nid;
	int r = 0; /* Success */

	nid = sshkey_curve_name_to_nid(strstr(ktype, "nistp"));
	// set nid in key
    key->ecdsa_nid = nid;

	if ((r = sshbuf_get_string(b, &ptr, &len)) < 0)
		return r;

	if (!ptr || len != ssh_ecdsa_ibm_protk_size(key)) {
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
	key->ecdsa_nid = nid;

	ptr = NULL;

out:
	if (ptr)
		free(ptr);
	return r;
}

static int ecdsa_sign_enc_cpacf(int nid, const uint8_t *protkey,
				const uint8_t *wkvp, const uint8_t *hash,
				int hashlen, BIGNUM *bn_r, BIGNUM *bn_s)
{
	const struct kdsa_entry_s *ke;
	uint8_t param[4096];
	BIGNUM *rcbn;
	int off, rc;

	ke = find_kdsa_entry(KEY_ECDSA, nid);
	if (!ke) {
		fprintf(stderr, "%s: unknown/unsupported nid %d\n", __func__,
			nid);
		return SSH_ERR_INTERNAL_ERROR;
	}
	off = ke->fsize - ke->d_size;

	memset(param, 0, sizeof(param));

	if (hashlen < ke->fsize) {
		int h_off = ke->fsize - hashlen;
		memcpy(param + 2 * ke->fsize + h_off, hash, hashlen);
	} else {
		memcpy(param + 2 * ke->fsize, hash, ke->fsize);
	}

	/*
	 * priv key d - protected key, so only encrypted key part
	 * we assume this prot key has fsize not d_size
	 */
	memcpy(param + 3 * ke->fsize, protkey, ke->fsize);

	getrandom(param + 4 * ke->fsize, ke->fsize, 0);

	/* the AES WK VP part for this prot key needs to go here: */
	memcpy(param + 5 * ke->fsize, wkvp, IBM_PROTK_AES_WK_VP_SIZE);

	/* KDSA instruction*/
	rc = s390_kdsa(ke->sign_enc_fc, param, 0, 0);
	if (rc == 0) {
		/* signature r and s */
		if ((rcbn = BN_bin2bn(param             + off, ke->d_size, bn_r)) == NULL)
			return SSH_ERR_INTERNAL_ERROR;
		if ((rcbn = BN_bin2bn(param + ke->fsize + off, ke->d_size, bn_s)) == NULL)
			return SSH_ERR_INTERNAL_ERROR;
	} else {
		return SSH_ERR_NEED_REKEY;
	}

	return rc;
}

static int
ssh_ecdsa_ibm_protk_copy_public(const struct sshkey *from, struct sshkey *to)
{
	return sshkey_ecdsa_funcs.copy_public(from, to);
}

static int
ssh_ecdsa_ibm_protk_sign(struct sshkey *key, u_char **sigp, size_t *lenp,
			 const u_char *data, size_t dlen, const char *alg,
			 const char *sk_provider, const char *sk_pin,
			 u_int compat)
{
	int len = 0, ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *bb = NULL;
	u_char digest[EVP_MAX_MD_SIZE];
	BIGNUM *sig_r, *sig_s;
	size_t digest_len;
	int hash_alg;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->wkvp == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1 ||
	    (digest_len = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;
	if ((ret = ssh_digest_memory(hash_alg, data, dlen,
	    digest, sizeof(digest))) != 0)
		goto out;

	/* BEGIN PKEY PART */
	if ((sig_r = BN_new()) == NULL || (sig_s = BN_new()) == NULL)
		goto out;

	ret = ecdsa_sign_enc_cpacf(key->ecdsa_nid, key->protk, key->wkvp,
				   digest, digest_len, sig_r, sig_s);
	if (ret != 0)
		goto out;
	/* END PKEY PART */

	if ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		goto out;
	if ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
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
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	sshbuf_free(b);
	sshbuf_free(bb);
	return ret;
}

static int
ssh_ecdsa_ibm_protk_verify(const struct sshkey *key,
			   const u_char *sig, size_t siglen,
			   const u_char *data, size_t dlen, const char *alg,
			   u_int compat, struct sshkey_sig_details **detailsp)
{
	return sshkey_ecdsa_funcs.verify(key, sig, siglen, data, dlen, alg,
					 compat, detailsp);
}

static const struct sshkey_impl_funcs sshkey_ibm_protkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_ibm_protk_size,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_ecdsa_ibm_protk_cleanup,
	/* .equal = */		ssh_ecdsa_ibm_protk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_ibm_protk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_ibm_protk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_ibm_protk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_ibm_protk_deserialize_private,
	/* .generate = */	NULL,
	/* .copy_public = */	ssh_ecdsa_ibm_protk_copy_public,
	/* .sign = */		ssh_ecdsa_ibm_protk_sign,
	/* .verify = */		ssh_ecdsa_ibm_protk_verify,
};

const struct sshkey_impl sshkey_ibm_protk_ecdsa_nistp256_impl = {
	/* .name = */		"ibm-protk-ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA-IBM-PROTK",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_IBM_PROTK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ibm_protkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ibm_protk_ecdsa_nistp384_impl = {
	/* .name = */		"ibm-protk-ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA-IBM-PROTK",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_IBM_PROTK,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ibm_protkey_ecdsa_funcs,
};

#ifdef OPENSSL_HAS_NISTP521
const struct sshkey_impl sshkey_ibm_protk_ecdsa_nistp521_impl = {
	/* .name = */		"ibm-protk-ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA-IBM-PROTK",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_IBM_PROTK,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ibm_protkey_ecdsa_funcs,
};
#endif /* OPENSSL_HAS_NISTP521 */
#endif /* WITH_OPENSSL && OPENSSL_HAS_ECC */
#endif /* s390x Architecture */
