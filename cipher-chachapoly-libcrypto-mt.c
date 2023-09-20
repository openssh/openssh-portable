/*
 * Copyright (c) 2023 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Mitchell Dorrell <mwd@psc.edu>
 *  Author: Chris Rapier  <rapier@psc.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the MIT License for more details.
 *
 * You should have received a copy of the MIT License along with this library;
 * if not, see http://opensource.org/licenses/MIT.
 *
 */

/* TODO: audit includes */

#include "includes.h"
#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"
#endif

#if defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#include <sys/types.h>
#include <unistd.h> /* needed for getpid under C99 */
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */
#include <pthread.h>

#include <openssl/evp.h>

#include "defines.h"
#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"

#include "xmalloc.h"
#include "cipher-chachapoly.h"
#include "cipher-chachapoly-libcrypto-mt.h"

#ifndef likely
# define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* Size of keystream to pregenerate, measured in bytes
 * we want to round up to the nearest chacha block and have
 * 128 bytes for overhead */
#define ROUND_UP(x,y) (((((x)-1)/(y))+1)*(y))
#define KEYSTREAMLEN (ROUND_UP((SSH_IOBUFSZ) + 128, (CHACHA_BLOCKLEN)))

/* BEGIN TUNABLES */

/* Number of worker threads to spawn. */
/* the goal is to ensure that main is never
 * waiting on the worker threads for keystream data */
#define NUMTHREADS 1

/* 64 seems to be a pretty blance between memory and performance
 * 128 is another option with somewhat higher memory consumption */
#define NUMSTREAMS 64

/* END TUNABLES */

struct mt_keystream {
	u_char poly_key[POLY1305_KEYLEN];     /* POLY1305_KEYLEN == 32 */
	u_char headerStream[CHACHA_BLOCKLEN]; /* CHACHA_BLOCKLEN == 64 */
	u_char mainStream[KEYSTREAMLEN];      /* KEYSTREAMLEN == 32768 */
};

struct threadData {
	EVP_CIPHER_CTX * main_evp;
	EVP_CIPHER_CTX * header_evp;
	u_char seqbuf[16];
};

struct mt_keystream_batch {
	u_int batchID;
	struct threadData tds[NUMTHREADS];
	struct mt_keystream streams[NUMSTREAMS];
};

struct chachapoly_ctx_mt {
	u_int seqnr;
	u_int batchID;

	struct mt_keystream_batch batches[2];

	pthread_t manager_tid[2];
	pthread_t self_tid;

	pid_t mainpid;
	u_char zeros[KEYSTREAMLEN]; /* KEYSTREAMLEN == 32768 */

  /* if OpenSSL has support for Poly1305 in the MAC EVPs
   * use that (OSSL >= 3.0) if not then it's OSSL 1.1 so
   * use the Poly1305 digest methods. Failing that use the
   * internal poly1305 methods */
#ifdef OPENSSL_HAVE_POLY_EVP
	EVP_MAC_CTX    *poly_ctx;
#elif !defined(WITH_OPENSSL3) && defined(EVP_PKEY_POLY1305)
	EVP_PKEY_CTX   *poly_ctx;
	EVP_MD_CTX     *md_ctx;
	EVP_PKEY       *pkey;
	size_t         ptaglen;
#else
	char           *poly_ctx;
#endif
};

struct manager_thread_args {
	struct chachapoly_ctx_mt * ctx_mt;
	u_int oldBatchID;
	int retval;
};

struct worker_thread_args {
	u_int batchID;
	struct mt_keystream_batch * batch;
	int threadIndex;
	u_char * zeros;
	int retval;
};

/* generate the keystream and header
 * we use nulls for the "data" (the zeros variable) in order to
 * get the raw keystream
 * Returns 0 on success and -1 on failure */
int
generate_keystream(struct mt_keystream * ks, u_int seqnr,
    struct threadData * td, u_char * zeros)
{
	/* generate poly1305 key */
	memset(td->seqbuf, 0, sizeof(td->seqbuf));
	POKE_U64(td->seqbuf + 8, seqnr);
	memset(ks->poly_key , 0, sizeof(ks->poly_key));
	if (!EVP_CipherInit(td->main_evp, NULL, NULL, td->seqbuf, 1) ||
	    EVP_Cipher(td->main_evp, ks->poly_key, ks->poly_key,
	    sizeof(ks->poly_key)) < 0)
		return -1;

	/* generate header keystream for encrypting payload length */
	if (!EVP_CipherInit(td->header_evp, NULL, NULL, td->seqbuf, 1) ||
	    EVP_Cipher(td->header_evp, ks->headerStream, zeros, CHACHA_BLOCKLEN)
	    < 0 )
		return -1;

	/* generate main keystream for encrypting payload */
	td->seqbuf[0] = 1;
	if (!EVP_CipherInit(td->main_evp, NULL, NULL, td->seqbuf, 1) ||
	    EVP_Cipher(td->main_evp, ks->mainStream, zeros, KEYSTREAMLEN) < 0)
		return -1;

	return 0;
}

/* free the EVP contexts associated with the give thread */
void
free_threadData(struct threadData * td)
{
	if (td == NULL)
		return;
	if (td->main_evp) /* false if initialization didn't get this far */
		EVP_CIPHER_CTX_free(td->main_evp);
	if (td->header_evp) /* false if initialization didn't get this far */
		EVP_CIPHER_CTX_free(td->header_evp);
	explicit_bzero(td, sizeof(*td));
}

/* initialize the EVPs used by the worker thread
   Returns 0 on success and -1 on failure */
int
initialize_threadData(struct threadData * td, const u_char *key)
{
	memset(td,0,sizeof(*td));
	if ((td->main_evp = EVP_CIPHER_CTX_new()) == NULL ||
	    (td->header_evp = EVP_CIPHER_CTX_new()) == NULL)
		goto fail;
	if (!EVP_CipherInit(td->main_evp, EVP_chacha20(), key, NULL, 1))
		goto fail;
	if (!EVP_CipherInit(td->header_evp, EVP_chacha20(), key + 32, NULL, 1))
		goto fail;
	if (EVP_CIPHER_CTX_iv_length(td->header_evp) != 16)
		goto fail;
	return 0;
 fail:
	free_threadData(td);
	return -1;
}

struct worker_thread_args *
worker_thread(struct worker_thread_args * args)
{
	/* check first */
	if (args == NULL)
		return NULL;
	if (args->batch == NULL || args->zeros == NULL) {
		args->retval = 1;
		return args;
	}

	int threadIndex = args->threadIndex;
	struct threadData * td = &(args->batch->tds[threadIndex]);
	u_int refseqnr = args->batchID * NUMSTREAMS;

	for (int i = threadIndex; i < NUMSTREAMS; i += NUMTHREADS) {
		if (generate_keystream(&(args->batch->streams[i]), refseqnr + i,
		    td, args->zeros) == -1) {
			args->retval = 1;
			return args;
		}
	}

	args->retval = 0;
	return args;
}

int
join_manager_thread(pthread_t manager_tid)
{
	struct manager_thread_args * args;
	if (pthread_join(manager_tid, (void **) &args) == 0) {
		if (args == NULL) {
			debug_f("Manager thread returned NULL!");
			return 1;
		} else if (args == PTHREAD_CANCELED) {
			debug_f("Manager thread canceled!");
			return 1;
		} else if (args->retval != 0) {
			debug_f("Manager thread error (%d)", args->retval);
			free(args);
			return 1;
		} else {
			free(args);
			return 0;
		}
	} else {
		debug_f("pthread_join error!");
		return 1;
	}
}

void
chachapoly_free_mt(struct chachapoly_ctx_mt * ctx_mt)
{
	if (ctx_mt == NULL)
		return;

#ifdef OPENSSL_HAVE_POLY_EVP
	if (ctx_mt->poly_ctx != NULL) {
		EVP_MAC_CTX_free(ctx_mt->poly_ctx);
		ctx_mt->poly_ctx = NULL;
	}
#elif !defined(WITH_OPENSSL3) && defined(EVP_PKEY_POLY1305)
	if (ctx_mt->md_ctx != NULL) {
		EVP_MD_CTX_free(ctx_mt->md_ctx);
		ctx_mt->md_ctx = NULL;
	}
	if (ctx_mt->pkey != NULL) {
		EVP_PKEY_free(ctx_mt->pkey);
		ctx_mt->pkey = NULL;
	}
#endif

	/*
	 * Only cleanup the manager threads if we are the PID that initialized
	 * them! If we're a fork, the threads don't really exist.
	 */

	if (getpid() == ctx_mt->mainpid) {
		if (ctx_mt->manager_tid[0] != ctx_mt->self_tid) {
			join_manager_thread(ctx_mt->manager_tid[0]);
			ctx_mt->manager_tid[0] = ctx_mt->self_tid;
		}
		if (ctx_mt->manager_tid[1] != ctx_mt->self_tid) {
			join_manager_thread(ctx_mt->manager_tid[1]);
			ctx_mt->manager_tid[1] = ctx_mt->self_tid;
		}
	}

	/* Cleanup thread data structures. */
	for (int i=0; i<2; i++)
		for (int j=0; j<NUMTHREADS; j++)
			free_threadData(&(ctx_mt->batches[i].tds[j]));

	/* Zero and free the whole multithreaded cipher context. */
	freezero(ctx_mt, sizeof(*ctx_mt));

	return;
}

struct chachapoly_ctx_mt *
chachapoly_new_mt(u_int startseqnr, const u_char * key, u_int keylen)
{
	struct chachapoly_ctx_mt * ctx_mt = xmalloc(sizeof(*ctx_mt));
	memset(ctx_mt, 0, sizeof(*ctx_mt));
	/* Initialize the sequence number. When rekeying, this won't be zero. */
	ctx_mt->seqnr = startseqnr;
	ctx_mt->batchID = startseqnr / NUMSTREAMS;
	struct threadData mainData;
	int tDataI;
	int genKSfailed = 0;

#ifdef OPENSSL_HAVE_POLY_EVP
	EVP_MAC *mac = NULL;
	if ((mac = EVP_MAC_fetch(NULL, "POLY1305", NULL)) == NULL)
		goto fail;
	if ((ctx_mt->poly_ctx = EVP_MAC_CTX_new(mac)) == NULL)
		goto fail;
#elif !defined(WITH_OPENSSL3) && defined(EVP_PKEY_POLY1305)
	if ((ctx_mt->md_ctx = EVP_MD_CTX_new()) == NULL)
		goto fail;
	if ((ctx_mt->pkey = EVP_PKEY_new_mac_key(EVP_PKEY_POLY1305, NULL,
	    ctx_mt->zeros, POLY1305_KEYLEN)) == NULL)
		goto fail;
	if (EVP_DigestSignInit(ctx_mt->md_ctx, &ctx_mt->poly_ctx, NULL, NULL,
	    ctx_mt->pkey) == 0)
		goto fail;
#else
	ctx_mt->poly_ctx = NULL;
#endif

	ctx_mt->batches[ctx_mt->batchID % 2].batchID = ctx_mt->batchID;
	ctx_mt->batches[(ctx_mt->batchID + 1) % 2].batchID =
	    ctx_mt->batchID + 1;

	/* initialize batches[0] tds */
	for (tDataI = 0; tDataI < NUMTHREADS; tDataI++) {
		if (initialize_threadData(&(ctx_mt->batches[0].tds[tDataI]),
		    key) != 0)
			break;
	}
	if (tDataI < NUMTHREADS) {
		/* Backtrack starting with 'tDataI - 1' */
		for (tDataI--; tDataI >= 0; tDataI--)
			free_threadData(&(ctx_mt->batches[0].tds[tDataI]));
		goto fail;
	}
	/* initialize batches[1] tds */
	for (tDataI = 0; tDataI < NUMTHREADS; tDataI++) {
		if (initialize_threadData(&(ctx_mt->batches[1].tds[tDataI]),
		    key) != 0)
			break;
	}
	if (tDataI < NUMTHREADS) {
		/* Backtrack starting with 'tDataI - 1' */
		for (tDataI--; tDataI >= 0; tDataI--)
			free_threadData(&(ctx_mt->batches[1].tds[tDataI]));
		/* Free the batches[0] tds too */
		for (tDataI = NUMTHREADS; tDataI >= 0; tDataI--)
			free_threadData(&(ctx_mt->batches[0].tds[tDataI]));
		goto fail;
	}

	if (initialize_threadData(&mainData, key) != 0) {
		chachapoly_free_mt(ctx_mt);
		explicit_bzero(&startseqnr, sizeof(startseqnr));
		return NULL;
	}

	for (int i=0; i<2; i++) {
		u_int refseqnr = ctx_mt->batches[i].batchID * NUMSTREAMS;
		for (int j = startseqnr > refseqnr ? startseqnr - refseqnr : 0;
		     j<NUMSTREAMS; j++) {
			if (generate_keystream(&(ctx_mt->batches[i].streams[j]),
			    refseqnr + j, &mainData, ctx_mt->zeros) == -1) {
				debug_f("generate_keystream failed in "
				    "chacha20-poly1305@hpnssh.org");
				genKSfailed = 1;
				break; /* imperfect, but it helps */
			}
		}
	}

	free_threadData(&mainData);

	if (genKSfailed != 0) {
		chachapoly_free_mt(ctx_mt);
		explicit_bzero(&startseqnr, sizeof(startseqnr));
		return NULL;
	}

	/* Store the PID so that in the future, we can tell if we're a fork */
	ctx_mt->mainpid = getpid();
	ctx_mt->self_tid = pthread_self();
	ctx_mt->manager_tid[0] = ctx_mt->self_tid;
	ctx_mt->manager_tid[1] = ctx_mt->self_tid;
	/* was reporting the TID using gettid() but it's not portable */
	debug2_f("<main thread: pid=%u, ptid=0x%lx>", getpid(), pthread_self());

	/* Success! */
	explicit_bzero(&startseqnr, sizeof(startseqnr));
	return ctx_mt;

 fail:
#ifdef OPENSSL_HAVE_POLY_EVP
	if (ctx_mt->poly_ctx != NULL) {
		EVP_MAC_CTX_free(ctx_mt->poly_ctx);
		ctx_mt->poly_ctx = NULL;
	}
#elif !defined(WITH_OPENSSL3) && defined(EVP_PKEY_POLY1305)
	if (ctx_mt->md_ctx != NULL) {
		EVP_MD_CTX_free(ctx_mt->md_ctx);
		ctx_mt->md_ctx = NULL;
	}
	if (ctx_mt->pkey != NULL) {
		EVP_PKEY_free(ctx_mt->pkey);
		ctx_mt->pkey = NULL;
	}
#endif
	freezero(ctx_mt, sizeof(*ctx_mt));
	explicit_bzero(&startseqnr, sizeof(startseqnr));
	return NULL;
}

/* a fast method to XOR the keystream against the data */
static inline void
fastXOR(u_char *dest, const u_char *src, const u_char *keystream, u_int len)
{

	/* XXX: this was __uint128_t but that was causing unaligned load errors.
	 * this works but we need to explore it more. */
	typedef uint32_t chunk;
	size_t i;

	for (i=0; i < (len / sizeof(chunk)); i++)
		((chunk *)dest)[i]=((chunk *)src)[i]^((chunk *)keystream)[i];
	for (i=i*(sizeof(chunk) / sizeof(char)); i < len; i++)
		dest[i]=src[i]^keystream[i];
}

struct manager_thread_args *
manager_thread(struct manager_thread_args * margs) {
	/* make sure we have valid data before proceeding */
	if (margs == NULL)
		return NULL;

	struct chachapoly_ctx_mt * ctx_mt = margs->ctx_mt;
	if (ctx_mt == NULL) {
		margs->retval = 1;
		return margs;
	}

	u_int oldBatchID = margs->oldBatchID;

	struct mt_keystream_batch * batch = &(ctx_mt->batches[oldBatchID % 2]);
	if (batch->batchID != oldBatchID) {
		debug_f("Post-crypt batch miss! Seeking %u, found %u. Failing.",
		    oldBatchID, batch->batchID);
		margs->retval = 1;
		return margs;
	}

	margs->retval = 0;
	u_int batchID = oldBatchID + 2;

	pthread_t tid[NUMTHREADS];
	struct worker_thread_args * wargs = malloc(NUMTHREADS * sizeof(*wargs));
	int ti;

	for (ti = 0; ti < NUMTHREADS; ti++) {
		wargs[ti].batchID = batchID;
		wargs[ti].batch = batch;
		wargs[ti].threadIndex = ti;
		wargs[ti].zeros = ctx_mt->zeros;
		if (pthread_create(&(tid[ti]), NULL, (void *) worker_thread,
		    &(wargs[ti])) != 0) {
			margs->retval = 1;
			break;
		}
	}
	for (; ti < NUMTHREADS; ti++) /* for error condition */
		tid[ti] = pthread_self();

	struct worker_thread_args * retwargs;

	for (ti = 0; ti < NUMTHREADS; ti++) {
		if (tid[ti] == pthread_self()) {
			margs->retval = 1; /* redundant, but harmless */
			continue;
		}
		if (pthread_join(tid[ti], (void **) &retwargs) == 0) {
			if (retwargs == NULL) {
				debug_f("Worker thread returned NULL!");
				margs->retval = 1;
			} else if (retwargs == PTHREAD_CANCELED) {
				debug_f("Worker thread canceled!");
				margs->retval = 1;
			} else {
				if (retwargs->retval != 0) {
					debug_f("Worker thread error (%d)",
					    retwargs->retval);
					margs->retval = 1;
				}
				if (retwargs != &(wargs[ti])) {
					debug_f("Worker thread didn't return "
					    "expected structure!");
					margs->retval = 1;
				}
			}
		} else {
			debug_f("pthread_join error!");
			margs->retval = 1;
		}
	}
	free(wargs);

	if (margs->retval == 0) {
		batch->batchID = batchID;
	}

	return margs;
}

int
chachapoly_crypt_mt(struct chachapoly_ctx_mt *ctx_mt, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
#ifdef SAFETY
	if (ctx_mt->mainpid != getpid()) { /* we're a fork */
		/*
		 * TODO: this is EXTREMELY RARE, may never happen at all (only
		 * if the fork calls crypt), so we should tell the compiler.
		 */
		/* The worker threads don't exist, we could spawn them? */
		debug_f("Fork called crypt without workers!");
		chachapoly_free_mt(ctx_mt);
		return SSH_ERR_INTERNAL_ERROR;
	}
#endif

	pthread_t * manager_tid = &(ctx_mt->manager_tid[ctx_mt->batchID % 2]);
	if (unlikely(*manager_tid != ctx_mt->self_tid)) {
		int ret = join_manager_thread(*manager_tid);
		*manager_tid = ctx_mt->self_tid;
		if (ret != 0)
			return SSH_ERR_INTERNAL_ERROR;
	}

	struct mt_keystream_batch * batch =
	    &(ctx_mt->batches[ctx_mt->batchID % 2]);

	struct mt_keystream * ks = &(batch->streams[seqnr % NUMSTREAMS]);

	int r = SSH_ERR_INTERNAL_ERROR;

#ifdef SAFETY
	if (batch->batchID == ctx_mt->batchID) { /* Safety check */
#endif
		/* check tag before anything else */
		if (!do_encrypt) {
			const u_char *tag = src + aadlen + len;
			u_char expected_tag[POLY1305_TAGLEN];
#if !defined(WITH_OPENSSL3) && defined(EVP_PKEY_POLY1305)
			if ((EVP_PKEY_CTX_ctrl(ctx_mt->poly_ctx, -1,
			    EVP_PKEY_OP_SIGNCTX, EVP_PKEY_CTRL_SET_MAC_KEY,
			    POLY1305_KEYLEN, ks->poly_key) <= 0) ||
			    (EVP_DigestSignUpdate(ctx_mt->md_ctx, src, aadlen + len) == 0)) {
				debug_f("SSL error while decrypting poly1305 tag");
				return SSH_ERR_INTERNAL_ERROR;
			}
			ctx_mt->ptaglen = POLY1305_TAGLEN;
			if (EVP_DigestSignFinal(ctx_mt->md_ctx, expected_tag,
			    &ctx_mt->ptaglen) == 0) {
				debug_f("SSL error while finalizing decyrpted poly1305");
				return SSH_ERR_INTERNAL_ERROR;
			}
#else
			poly1305_auth(ctx_mt->poly_ctx, expected_tag, src,
			    aadlen + len, ks->poly_key);
#endif
			if (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN)
			    != 0)
				r = SSH_ERR_MAC_INVALID;
			explicit_bzero(expected_tag, sizeof(expected_tag));
		}
		if (r != SSH_ERR_MAC_INVALID) {
			/* Crypt additional data (i.e., packet length) */
			/* TODO: is aadlen always four bytes? */
			/* TODO: do we always have an aadlen? */
			if (aadlen)
				for (u_int i=0; i<aadlen; i++)
					dest[i] = ks->headerStream[i] ^ src[i];
			/* Crypt payload */
			fastXOR(dest+aadlen,src+aadlen,ks->mainStream,len);
			/* calculate and append tag */
#if !defined(WITH_OPENSSL3) && defined(EVP_PKEY_POLY1305)
			if (do_encrypt) {
				if ((EVP_PKEY_CTX_ctrl(ctx_mt->poly_ctx, -1,
				    EVP_PKEY_OP_SIGNCTX, EVP_PKEY_CTRL_SET_MAC_KEY,
				    POLY1305_KEYLEN, ks->poly_key) <=0) ||
				    (EVP_DigestSignUpdate(ctx_mt->md_ctx, dest, aadlen + len) == 0)) {
					debug_f ("SSL error while encrypting poly1305 tag");
					return SSH_ERR_INTERNAL_ERROR;
				}
				ctx_mt->ptaglen = POLY1305_TAGLEN;
				if (EVP_DigestSignFinal(ctx_mt->md_ctx, dest+aadlen+len,
				    &ctx_mt->ptaglen) == 0) {
					debug_f("SSL error while finalizing decyrpted poly1305");
					return SSH_ERR_INTERNAL_ERROR;
				}
			}
#else
			if (do_encrypt)
				poly1305_auth(ctx_mt->poly_ctx, dest+aadlen+len,
				    dest, aadlen+len, ks->poly_key);
#endif
			r=0; /* Success! */
		}
		if (r) /* Anything nonzero is an error. */
			return r;

		ctx_mt->seqnr = seqnr + 1;

		if (unlikely(ctx_mt->seqnr / NUMSTREAMS > ctx_mt->batchID)) {
			struct manager_thread_args * args =
			    malloc(sizeof(*args));
			if (args == NULL) {
				return SSH_ERR_INTERNAL_ERROR;
			}
			args->ctx_mt = ctx_mt;
			args->oldBatchID = ctx_mt->batchID;
			if (pthread_create(&(ctx_mt->manager_tid[ctx_mt->batchID
			    % 2]), NULL, (void *) manager_thread, args) != 0) {
				free(args);
				return SSH_ERR_INTERNAL_ERROR;
			}
			ctx_mt->batchID = ctx_mt->seqnr / NUMSTREAMS;
		}

		/* TODO: Nothing we need to sanitize here? */

		return 0;
#ifdef SAFETY
	} else { /* Bad, it's the wrong batch. */
		debug_f( "Pre-crypt batch miss! Seeking %u, found %u. Failing.",
		    ctx_mt->batchID, batch->batchID);
		return SSH_ERR_INTERNAL_ERROR;
	}
#endif
}

int
chachapoly_get_length_mt(struct chachapoly_ctx_mt *ctx_mt, u_int *plenp,
    u_int seqnr, const u_char *cp, u_int len)
{
	/* TODO: add compiler hints */
#ifdef SAFETY
	if (ctx_mt->mainpid != getpid()) { /* Use serial mode if we're a fork */
		debug_f("We're a fork. Failing.");
		return SSH_ERR_INTERNAL_ERROR;
	}
#endif

	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;

	pthread_t * manager_tid = &(ctx_mt->manager_tid[ctx_mt->batchID % 2]);
	if (unlikely(*manager_tid != ctx_mt->self_tid)) {
		int ret = join_manager_thread(*manager_tid);
		*manager_tid = ctx_mt->self_tid;
		if (ret != 0)
			return SSH_ERR_INTERNAL_ERROR;
	}

	u_char buf[4];
#ifdef SAFETY
	u_int sought_batchID = seqnr / NUMSTREAMS;
#endif
	struct mt_keystream_batch * batch =
	    &(ctx_mt->batches[ctx_mt->batchID % 2]);
	struct mt_keystream * ks = &(batch->streams[seqnr % NUMSTREAMS]);
#ifdef SAFETY
	if (batch->batchID == sought_batchID) {
#endif
		for (u_int i=0; i < sizeof(buf); i++)
			buf[i]=ks->headerStream[i] ^ cp[i];
		*plenp = PEEK_U32(buf);
		return 0;
#ifdef SAFETY
	} else {
		debug_f("Batch miss! Seeking %u, found %u. Failing.",
		    sought_batchID, batch->batchID);
		return SSH_ERR_INTERNAL_ERROR;
	}
#endif
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
