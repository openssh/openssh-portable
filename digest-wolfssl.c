/*
 * WolfSSL digest
 */
#include "includes.h"

#ifdef USING_WOLFSSL

#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/ripemd.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#include "buffer.h"
#include "digest.h"

typedef void md_init_fn(void *mdctx);
typedef void md_update_fn(void *mdctx, const u_int8_t *m, size_t mlen);
typedef void md_final_fn(void *mdctx, u_int8_t[]);

struct ssh_digest_ctx {
	int alg;
	void *mdctx;
};

struct ssh_digest {
	int id;
	const char *name;
	size_t block_len;
	size_t digest_len;
	size_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
const struct ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_SIZE,
		MD5_DIGEST_SIZE,
		sizeof(Md5),
		(md_init_fn *) wc_InitMd5,
		(md_update_fn *) wc_Md5Update,
		(md_final_fn *) wc_Md5Final
	},
	{
		SSH_DIGEST_RIPEMD160,
		"RIPEMD160",
		RIPEMD_BLOCK_SIZE,
		RIPEMD_DIGEST_SIZE,
		sizeof(RipeMd),
		(md_init_fn *) wc_InitRipeMd,
		(md_update_fn *) wc_RipeMdUpdate,
		(md_final_fn *) wc_RipeMdFinal
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA_BLOCK_SIZE,
		SHA_DIGEST_SIZE,
		sizeof(Sha),
		(md_init_fn *) wc_InitSha,
		(md_update_fn *) wc_ShaUpdate,
		(md_final_fn *) wc_ShaFinal
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_SIZE,
		SHA256_DIGEST_SIZE,
		sizeof(Sha256),
		(md_init_fn *) wc_InitSha256,
		(md_update_fn *) wc_Sha256Update,
		(md_final_fn *) wc_Sha256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_SIZE,
		SHA384_DIGEST_SIZE,
		sizeof(Sha384),
		(md_init_fn *) wc_InitSha384,
		(md_update_fn *) wc_Sha384Update,
		(md_final_fn *) wc_Sha384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_SIZE,
		SHA512_DIGEST_SIZE,
		sizeof(Sha512),
		(md_init_fn *) wc_InitSha512,
		(md_update_fn *) wc_Sha512Update,
		(md_final_fn *) wc_Sha512Final
	}
};

static const struct ssh_digest *
ssh_digest_by_alg(int alg)
{
	if (alg < 0 || alg >= SSH_DIGEST_MAX)
		return NULL;
	if (digests[alg].id != alg) /* sanity */
		return NULL;
	return &(digests[alg]);
}

size_t
ssh_digest_bytes(int alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);

	return digest == NULL ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(struct ssh_digest_ctx *ctx)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	return digest == NULL ? 0 : digest->block_len;
}

struct ssh_digest_ctx *
ssh_digest_start(int alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);
	struct ssh_digest_ctx *ret;

	if (digest == NULL || (ret = calloc(1, sizeof(ret))) == NULL)
		return NULL;
	if ((ret->mdctx = calloc(1, digest->ctx_len)) == NULL) {
		free(ret);
		return NULL;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	return ret;
}

int
ssh_digest_copy_state(struct ssh_digest_ctx *from, struct ssh_digest_ctx *to)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(from->alg);

	if (digest == NULL || from->alg != to->alg)
		return -1;
	memcpy(to->mdctx, from->mdctx, digest->ctx_len);
	return 0;
}

int
ssh_digest_update(struct ssh_digest_ctx *ctx, const void *m, size_t mlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	if (digest == NULL)
		return -1;
	digest->md_update(ctx->mdctx, m, mlen);
	return 0;
}

int
ssh_digest_update_buffer(struct ssh_digest_ctx *ctx, const Buffer *b)
{
	return ssh_digest_update(ctx, buffer_ptr(b), buffer_len(b));
}

int
ssh_digest_final(struct ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	if (digest == NULL)
		return -1;
	if (dlen > UINT_MAX)
		return -1;
	if (dlen < digest->digest_len) /* No truncation allowed */
		return -1;
	digest->md_final(ctx->mdctx, d);
	return 0;
}

void
ssh_digest_free(struct ssh_digest_ctx *ctx)
{
	const struct ssh_digest *digest;

	if (ctx != NULL) {
		digest = ssh_digest_by_alg(ctx->alg);
		if (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			free(ctx->mdctx);
			explicit_bzero(ctx, sizeof(*ctx));
			free(ctx);
		}
	}
}

int
ssh_digest_memory(int alg, const void *m, size_t mlen, u_char *d, size_t dlen)
{
	struct ssh_digest_ctx *ctx = ssh_digest_start(alg);

	if (ctx == NULL)
		return -1;
	if (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		return -1;
	ssh_digest_free(ctx);
	return 0;
}

int
ssh_digest_buffer(int alg, const Buffer *b, u_char *d, size_t dlen)
{
	return ssh_digest_memory(alg, buffer_ptr(b), buffer_len(b), d, dlen);
}

#endif /* USING_WOLFSSL */
