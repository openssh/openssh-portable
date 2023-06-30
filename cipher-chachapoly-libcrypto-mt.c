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
#define NUMSTREAMS 128

/* END TUNABLES */

struct mt_keystream {
	u_char poly_key[POLY1305_KEYLEN];     /* POLY1305_KEYLEN == 32 */
	u_char headerStream[CHACHA_BLOCKLEN]; /* CHACHA_BLOCKLEN == 64 */
	u_char mainStream[KEYSTREAMLEN];      /* KEYSTREAMLEN == 32768 */
};

struct mt_keystream_batch {
	u_int batchID;
	pthread_mutex_t lock;
	pthread_barrier_t bar_start;
	pthread_barrier_t bar_end;
	struct mt_keystream streams[NUMSTREAMS];
};

struct threadData {
	EVP_CIPHER_CTX * main_evp;
	EVP_CIPHER_CTX * header_evp;
	u_char seqbuf[16];

	u_int batchID;
};

struct chachapoly_ctx_mt {
	u_int seqnr;
	u_int batchID;
	pthread_mutex_t batchID_lock;

	struct mt_keystream_batch batches[2];

	pthread_t tid[NUMTHREADS];
	pthread_mutex_t tid_lock;
	pthread_t adv_tid;
	pthread_t self_tid;

	pid_t mainpid;
	pthread_cond_t cond;
	u_char zeros[KEYSTREAMLEN]; /* KEYSTREAMLEN == 32768 */
	struct threadData tds[NUMTHREADS];

  /* if OpenSSL has support for Poly1305 in the MAC EVPs
   * use that (OSSL >= 3.0) if not then it's OSSL 1.1 so
   * use the Poly1305 digest methods. Failing that use the
   * internal poly1305 methods */
#ifdef OPENSSL_HAVE_POLY_EVP
	EVP_MAC_CTX    *poly_ctx;
#elif (OPENSSL_VERSION_NUMBER < 0x30000000UL) && defined(EVP_PKEY_POLY1305)
	EVP_PKEY_CTX   *poly_ctx;
	EVP_MD_CTX     *md_ctx;
	EVP_PKEY       *pkey;
	size_t         ptaglen;
#else
	char           *poly_ctx;
#endif
};

/* generate the keystream and header
 * we use nulls for the "data" (the zeros variable) in order to
 * get the raw keystream
 * Returns 0 on success and -1 on failure */
int
generate_keystream(struct mt_keystream * ks,u_int seqnr,struct threadData * td,
    u_char * zeros)
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

/* continually load the keystream struct, which is part of the batch
 * struct, which is part of the ctx_mt struct with keystream data */
void
threadLoop (struct chachapoly_ctx_mt * ctx_mt)
{
	struct threadData * td;
	pthread_t self;
	int threadIndex = -1;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	/*
	 * Wait for main thread to fill in thread IDs. The main thread won't
	 * release the lock until it's safe to proceed.
	 */
	/* TODO: Add error checks for all pthread_mutex calls */
	pthread_mutex_lock(&(ctx_mt->tid_lock));
	/* We don't need to hold the lock for any reason. */
	pthread_mutex_unlock(&(ctx_mt->tid_lock));

	/* Initialize to an impossible number to enable error checking */
	threadIndex = -1;
	self = pthread_self();
	/* Get thread ID index */
	for (int i=0; i<NUMTHREADS; i++) {
		if (pthread_equal(self, ctx_mt->tid[i])) {
			threadIndex=i;
			break;
		}
	}
	if (threadIndex == -1) { /* the for-loop completed without matching */
		/* stderr is thread safe, but SSH debug() might not be */
		fprintf(stderr,"%s: Thread ID not found! Exiting!",__func__);
		return;
	}
	/* Now that we have the thread ID, grab the thread data. */
	td = &(ctx_mt->tds[threadIndex]);

	while (1) {
		/*
		 * This is mostly just textbook pthread_cond_wait(), used to
		 * wait for ctx_mt->batchID to change. Once the main thread
		 * changes ctx_mt->batchID, it broadcasts to ctx_mt->cond, which
		 * triggers all threads which were waiting at ctx_mt->cond to
		 * proceed. The threads check to see if ctx_mt->batchID REALLY
		 * changed (hypothetically, ctx_mt->cond could be erroneously
		 * triggered), and if so, proceed to generate the next batch.
		 *
		 * If a thread is canceled while it's holding batchID_lock, it
		 * must free that lock before terminating, so a cleanup handler
		 * is registered using pthread_cleanup_push(...) and later
		 * deregistered using pthread_cleanup_pop(0).
		 *
		 * By restricting cancellations to two carefully chosen points,
		 * we can ensure that the locks will be in a known state when
		 * the thread cancels, and so we can release them appropriately.
		 */
		pthread_mutex_lock(&(ctx_mt->batchID_lock));
		pthread_cleanup_push((void *) pthread_mutex_unlock,
		    &(ctx_mt->batchID_lock));
		while (td->batchID == ctx_mt->batchID) {
			/* Briefly allow cancellations here. */
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
			pthread_testcancel();
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			/*
			 * Definitely disallow cancellations DURING the
			 * cond_wait, otherwise it becomes impossible to
			 * destroy the locks using standard pthread calls.
			 */
			/* Wait for main to update batchID and signal us. */
			pthread_cond_wait(&(ctx_mt->cond),
			    &(ctx_mt->batchID_lock));
			/* Briefly allow cancellations again. */
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
			pthread_testcancel();
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		}
		pthread_cleanup_pop(0);
		/*
		 * The main thread changed ctx_mt->batchID, and we
		 * noticed, so update our internal value and move on.
		 */
		td->batchID = ctx_mt->batchID;
		pthread_mutex_unlock(&(ctx_mt->batchID_lock));

		struct mt_keystream_batch * oldBatch =
		    &(ctx_mt->batches[(td->batchID - 1) % 2]);

		u_int newBatchID = oldBatch->batchID + 2;
		u_int refseqnr = newBatchID * NUMSTREAMS;

		if (threadIndex == 0)
			pthread_mutex_lock(&(oldBatch->lock));
		pthread_barrier_wait(&(oldBatch->bar_start));

		/* generate keystream should always work but if it doesn't
		 * then we do a hard stop as progressing may result in
		 * corrupted data */
		for (int i = threadIndex; i < NUMSTREAMS; i += NUMTHREADS) {
			if (generate_keystream(&(oldBatch->streams[i]),
			      refseqnr + i, td, ctx_mt->zeros) == -1) {
				fatal_f("generate_keystream failed in chacha20-poly1305@hpnssh.org");
			}
		}

		pthread_barrier_wait(&(oldBatch->bar_end));
		oldBatch->batchID = newBatchID;
		if (threadIndex == 0)
			pthread_mutex_unlock(&(oldBatch->lock));
	}
	/* This will never happen. */
	return;
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
#endif

	/*
	 * Only cleanup the threads and mutexes if we are the PID that
	 * initialized them! If we're a fork, the threads don't really exist,
	 * and the the mutexes (and cond) are in an unknown state, which can't
	 * be safely destroyed.
	 */
	if (getpid() == ctx_mt->mainpid) {
		/*
		 * Acquire batchID_lock, so that thread cancellations can be
		 * sent without risking race conditions near cond. We don't need
		 * to acquire tid_lock, since we're only reading, and the main
		 * thread is the only writer, which is us!
		 */
		pthread_mutex_lock(&(ctx_mt->batchID_lock));
		for (int i=0; i<NUMTHREADS; i++)
			pthread_cancel(ctx_mt->tid[i]);
		pthread_mutex_unlock(&(ctx_mt->batchID_lock));
		/*
		 * At this point, the only threads which might not cancel are
		 * the ones currently stuck on pthread_cond_wait(), so free them
		 * now. There's a cancellation point immediately after the
		 * cond_wait() to prevent them from starting new work.
		 */
		for (int i=0; i<NUMTHREADS; i++)
			pthread_cond_broadcast(&(ctx_mt->cond));
		/* All threads are canceled or will cancel very soon. */
		for (int i=0; i<NUMTHREADS; i++) {
			debug2_f("Joining thread %d: %lx", i, ctx_mt->tid[i]);
			/*
			 * If the thread was already idle, this won't block.
			 * Busy threads will encounter a cancellation point when
			 * they finish their work.
			 */
			pthread_join(ctx_mt->tid[i], NULL);
			debug2_f("Joined thread %d", i);
		}
		/* All threads are joined. Everything is serial now. */
		pthread_mutex_destroy(&(ctx_mt->tid_lock));
		pthread_mutex_destroy(&(ctx_mt->batchID_lock));
		pthread_cond_destroy(&(ctx_mt->cond));
		for (int i=0; i<2; i++) {
			pthread_mutex_destroy(&(ctx_mt->batches[i].lock));
			pthread_barrier_destroy(
			    &(ctx_mt->batches[i].bar_start));
			pthread_barrier_destroy(&(ctx_mt->batches[i].bar_end));
		}
	}

	/* The threads are all dead, so cleanup their data structures. */
	for (int i=0; i<NUMTHREADS; i++)
		free_threadData(&(ctx_mt->tds[i]));

	/* Zero and free the whole multithreaded cipher context. */
	freezero(ctx_mt, sizeof(*ctx_mt));
}

struct chachapoly_ctx_mt *
chachapoly_new_mt(u_int startseqnr, const u_char * key, u_int keylen)
{
	struct chachapoly_ctx_mt * ctx_mt = xmalloc(sizeof(*ctx_mt));
	memset(ctx_mt, 0, sizeof(*ctx_mt));
	/* Initialize the sequence number. When rekeying, this won't be zero. */
	ctx_mt->seqnr = startseqnr;
	ctx_mt->batchID = startseqnr / NUMSTREAMS;

#ifdef OPENSSL_HAVE_POLY_EVP
	/* TODO: more error checks! */
	EVP_MAC *mac = NULL;
	if ((mac = EVP_MAC_fetch(NULL, "POLY1305", NULL)) == NULL) {
		freezero(ctx_mt, sizeof(*ctx_mt));
		explicit_bzero(&startseqnr, sizeof(startseqnr));
		return NULL;
	}
	if ((ctx_mt->poly_ctx = EVP_MAC_CTX_new(mac)) == NULL) {
		freezero(ctx_mt, sizeof(*ctx_mt));
		explicit_bzero(&startseqnr, sizeof(startseqnr));
		return NULL;
	}
#elif (OPENSSL_VERSION_NUMBER < 0x30000000UL) && defined(EVP_PKEY_POLY1305)
	ctx_mt->md_ctx = EVP_MD_CTX_new();
	ctx_mt->pkey = EVP_PKEY_new_mac_key(EVP_PKEY_POLY1305, NULL, ctx_mt->zeros,
	    POLY1305_KEYLEN);
	EVP_DigestSignInit(ctx_mt->md_ctx, &ctx_mt->poly_ctx, NULL, NULL, ctx_mt->pkey);
#else
	ctx_mt->poly_ctx = NULL;
#endif

	/* TODO: add error checks */
	pthread_mutex_init(&ctx_mt->batchID_lock, NULL);
	pthread_mutex_init(&(ctx_mt->tid_lock), NULL);
	pthread_cond_init(&(ctx_mt->cond), NULL);

	ctx_mt->batches[ctx_mt->batchID % 2].batchID = ctx_mt->batchID;
	ctx_mt->batches[(ctx_mt->batchID + 1) % 2].batchID = ctx_mt->batchID + 1;

	for (int i=0; i<2; i++) {
		struct mt_keystream_batch * batch = &(ctx_mt->batches[i]);
		pthread_mutex_init(&(batch->lock), NULL);
		pthread_barrier_init(&(batch->bar_start), NULL, NUMTHREADS);
		pthread_barrier_init(&(batch->bar_end), NULL, NUMTHREADS);
	}

	for (int i=0; i<NUMTHREADS; i++) {
		initialize_threadData(&(ctx_mt->tds[i]), key);
		ctx_mt->tds[i].batchID = ctx_mt->batchID;
	}

	struct threadData * mainData;

#if NUMTHREADS == 0
	/* There are none to borrow, so initialize our own. */
	struct threadData td;
	initialize_threadData(&td, key)
	mainData = &td;
#else
	/* Borrow ctx_mt->tds[0] to do initial keystream generation. */
	mainData = &(ctx_mt->tds[0]);
#endif

	for (int i=0; i<2; i++) {
		u_int refseqnr = ctx_mt->batches[i].batchID * NUMSTREAMS;
		for (int j = startseqnr > refseqnr ? startseqnr - refseqnr : 0;
		     j<NUMSTREAMS; j++) {
			if (generate_keystream(&(ctx_mt->batches[i].streams[j]),
			    refseqnr + j, mainData, ctx_mt->zeros) == -1) {
				fatal_f("generate_keystream failed in chacha20-poly1305@hpnssh.org");
			}
		}
	}

#if NUMTHREADS == 0
	free_threadData(&td);
#endif

	/* Spawn threads. */

	/* Store the PID so that in the future, we can tell if we're a fork */
	ctx_mt->mainpid = getpid();
	ctx_mt->self_tid = pthread_self();
	ctx_mt->adv_tid = ctx_mt->self_tid;
	int ret=0;
	/* Block workers from reading their thread IDs before we set them. */
	pthread_mutex_lock(&(ctx_mt->tid_lock));
	/* was reporting the TID using gettid() but it's not portable */
	debug2_f("<main thread: pid=%u, ptid=0x%lx>", getpid(), pthread_self());
	for (int i=0; i<NUMTHREADS; i++) {
		/*
		 * If we fail to generate some threads, the thread ID will
		 * remain zeroed, which is unlikely to ever match a real thread,
		 * and so SHOULD be ignored by pthread_cancel and pthread_join
		 * while ctx_mt is being freed.
		 */
		if (pthread_create(&(ctx_mt->tid[i]), NULL,
		    (void *)threadLoop, ctx_mt)) {
			ret=1;
			break; /* No point in wasting time... */
		}
	}
	pthread_mutex_unlock(&(ctx_mt->tid_lock));
	if (ret) /* failed while starting a thread */
		goto failthreads;

	/* Success! */
	explicit_bzero(&startseqnr, sizeof(startseqnr));
	return ctx_mt;

 failthreads:
	chachapoly_free_mt(ctx_mt);
	explicit_bzero(&startseqnr, sizeof(startseqnr));
	return NULL;
}

/* a fast method to XOR the keystream against the data */
static inline void
fastXOR(u_char *dest, const u_char *src, const u_char *keystream, u_int len)
{

	/* XXX: this was __uint128_t but that was causing unaligned load errors. 
	 * this works but we need to explore it more. */
//	typedef __uint32_t chunk;
	size_t i;
	for (i=0; i < len; i++) 
		dest[i] = src[i]^keystream[i];
	
//	for (i=0; i < (len / sizeof(chunk)); i++)
//		((chunk *)dest)[i]=((chunk *)src)[i]^((chunk *)keystream)[i];
//	for (i=i*(sizeof(chunk) / sizeof(char)); i < len; i++)
//		dest[i]=src[i]^keystream[i];
}

void
adv_thread(struct chachapoly_ctx_mt * ctx_mt) {
	u_int newBatchID = ctx_mt->seqnr / NUMSTREAMS;
	struct mt_keystream_batch * newBatch =
	    &(ctx_mt->batches[newBatchID % 2]);
	pthread_mutex_lock(&(newBatch->lock));
	u_int found_batchID = newBatch->batchID;
	pthread_mutex_unlock(&(newBatch->lock));
	if (found_batchID != newBatchID) {
		debug_f("Post-crypt batch miss! Seeking %u, found %u. Looping.",
		    newBatchID, found_batchID);
		while (found_batchID != newBatchID) {
			pthread_mutex_lock(&(newBatch->lock));
			found_batchID = newBatch->batchID;
			pthread_mutex_unlock(&(newBatch->lock));
		}
		debug_f("Loop exit.");
	}

	pthread_mutex_lock(&(ctx_mt->batchID_lock));
	ctx_mt->batchID = ctx_mt->batchID + 1;
	pthread_mutex_unlock(&(ctx_mt->batchID_lock));

	pthread_cond_broadcast(&(ctx_mt->cond));
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
		/* The worker threads don't exist, so regenerate ctx_mt */
		debug_f("Fork called crypt without workers!");
		chachapoly_free_mt(ctx_mt);
		return SSH_ERR_INTERNAL_ERROR;
	}
#endif

	if (__builtin_expect(ctx_mt->adv_tid != ctx_mt->self_tid,0)) {
		pthread_join(ctx_mt->adv_tid, NULL);
		ctx_mt->adv_tid = ctx_mt->self_tid;
	}

	struct mt_keystream_batch * batch =
	    &(ctx_mt->batches[ctx_mt->batchID % 2]);
#ifdef SAFETY
	u_int found_batchID = batch->batchID;
#endif
	struct mt_keystream * ks = &(batch->streams[seqnr % NUMSTREAMS]);

	int r = SSH_ERR_INTERNAL_ERROR;

#ifdef SAFETY
	if (found_batchID == ctx_mt->batchID) { /* Safety check */
		explicit_bzero(&found_batchID, sizeof(found_batchID));
#endif
		/* check tag before anything else */
		if (!do_encrypt) {
			const u_char *tag = src + aadlen + len;
			u_char expected_tag[POLY1305_TAGLEN];
#if (OPENSSL_VERSION_NUMBER < 0x30000000UL) && defined(EVP_PKEY_POLY1305)
			EVP_PKEY_CTX_ctrl(ctx_mt->poly_ctx, -1, EVP_PKEY_OP_SIGNCTX, EVP_PKEY_CTRL_SET_MAC_KEY, POLY1305_KEYLEN, ks->poly_key);
			EVP_DigestSignUpdate(ctx_mt->md_ctx, src, aadlen + len);
			ctx_mt->ptaglen = POLY1305_TAGLEN;
			EVP_DigestSignFinal(ctx_mt->md_ctx, expected_tag, &ctx_mt->ptaglen);
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
#if (OPENSSL_VERSION_NUMBER < 0x30000000UL) && defined(EVP_PKEY_POLY1305)
			if (do_encrypt) {
				EVP_PKEY_CTX_ctrl(ctx_mt->poly_ctx, -1, EVP_PKEY_OP_SIGNCTX, EVP_PKEY_CTRL_SET_MAC_KEY, POLY1305_KEYLEN, ks->poly_key);
				EVP_DigestSignUpdate(ctx_mt->md_ctx, dest, aadlen + len);
				ctx_mt->ptaglen = POLY1305_TAGLEN;
				EVP_DigestSignFinal(ctx_mt->md_ctx, dest+aadlen+len, &ctx_mt->ptaglen);
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

		if (__builtin_expect(ctx_mt->seqnr / NUMSTREAMS > ctx_mt->batchID,0)) {
			pthread_create(&ctx_mt->adv_tid, NULL, (void *) adv_thread, ctx_mt);
			//adv_thread(ctx_mt);
		}

		/* TODO: Nothing we need to sanitize here? */

		return 0;
#ifdef SAFETY
	} else { /* Bad, it's the wrong batch. */
		debug_f( "Pre-crypt batch miss! Seeking %u, found %u. Failing.",
		    ctx_mt->batchID, found_batchID);
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

	if (ctx_mt->adv_tid != ctx_mt->self_tid) {
		pthread_join(ctx_mt->adv_tid, NULL);
		ctx_mt->adv_tid = ctx_mt->self_tid;
	}

	u_char buf[4];
#ifdef SAFETY
	u_int sought_batchID = seqnr / NUMSTREAMS;
	u_int found_batchID;
#endif
	struct mt_keystream_batch * batch =
	    &(ctx_mt->batches[ctx_mt->batchID % 2]);
	struct mt_keystream * ks = &(batch->streams[seqnr % NUMSTREAMS]);
#ifdef SAFETY
	found_batchID = batch->batchID;

	if (found_batchID == sought_batchID) {
		explicit_bzero(&found_batchID, sizeof(found_batchID));
#endif
		for (u_int i=0; i < sizeof(buf); i++)
			buf[i]=ks->headerStream[i] ^ cp[i];
		*plenp = PEEK_U32(buf);
		return 0;
#ifdef SAFETY
	} else {
		debug_f("Batch miss! Seeking %u, found %u. Failing.",
		    sought_batchID, found_batchID);
		explicit_bzero(&found_batchID, sizeof(found_batchID));
		return SSH_ERR_INTERNAL_ERROR;
	}
#endif
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
