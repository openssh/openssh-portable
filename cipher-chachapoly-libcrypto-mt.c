/* A multi-threaded implementation of the ChaCha20-Poly1305 cipher. */
/*
 * This is an alternative implementation, intended to be fully compatible with
 * preexisting implementations of ChaCha20-Poly1305 in OpenSSH. It is based upon
 * the sources of cipher-chachapoly-libcrypto.c, and similarly makes use of
 * OpenSSL's EVP interface to generate the ChaCha20 keystreams. The Poly1305
 * component is fulfilled using the Poly1305 algorithms which ship with OpenSSH.
 *
 * During initialization, this cipher spawns worker threads that pre-generate
 * all necessary ChaCha20 keystreams in advance. When the main OpenSSH thread
 * uses this cipher to encrypt or decrypt a packet, the pregenerated keystream
 * is read, they are merged with the packet payload via an XOR operation, the
 * Poly1305 tag is verified, and the worker threads are signalled that the
 * keystream memory can be reused to prepare for the encryption or decryption of
 * a subsequent packet.
 *
 * The serial functions from cipher-chachapoly-libcrypto.c may be used
 * interchangeably with the functions from this cipher, since they use
 * compatible context structure definitions. However, the serial cleanup
 * function, chachapoly_free(), does not properly clean up the worker threads
 * and free the additional structures needed for this multithreaded
 * implementation.
 */

/* The includes were mostly copied from cipher-chachapoly-libcrypto.c */
/* TODO: audit includes */

#include "includes.h"
#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"
#endif

#if defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#include <sys/types.h>
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

/* Size of keystream to pregenerate, measured in bytes */
#define KEYSTREAMLEN ((((SSH_IOBUFSZ - 1)/CHACHA_BLOCKLEN) + 1)*CHACHA_BLOCKLEN)


/* BEGIN TUNABLES */

/* Number of worker threads to spawn. */
#define NUMTHREADS 2

/* Number of keystreams to pre-generate. This does not need to be a multiple of
 * NUMTHREADS. Larger values will allocate more memory, while smaller values may
 * fail to absorb bursts of packets during moments of high throughput. The total
 * size of the keystream cache will be NUMSTREAMS*KEYSTREAMLEN, measured in
 * bytes. This cache is the primary contribution to the memory footprint of this
 * multithreaded cipher.
 */
#define NUMSTREAMS 32

/* When this value is exceeded, spawn a new worker thread. Not implemented. */
#define MAXSTRIKES 3

/* END TUNABLES */


/* all members are written by worker threads, read by main thread */
struct mt_keystream {
	u_char poly_key[POLY1305_KEYLEN];     /* POLY1305_KEYLEN == 32 */
	u_char headerStream[CHACHA_BLOCKLEN]; /* CHACHA_BLOCKLEN == 64 */
	u_char mainStream[KEYSTREAMLEN];      /* KEYSTREAMLEN == 32768 */

	/*
	 * Allow main thread to verify that the keystream was generated for the
	 * expected seqnr. Also allow worker threads to see if the keystream is
	 * old.
	 */
	u_int seqnr;

	/* Block the main thread from reading while a worker is writing */
	pthread_mutex_t lock;
};

/* Stores all nontrivial data used inside individual threads */
struct threadData {
	/* members for use in generate_keystream(): */
	EVP_CIPHER_CTX * main_evp;
	EVP_CIPHER_CTX * header_evp;
	u_char seqbuf[16];

	/* members for use in threadLoop(): */
	u_int seqnr;
};

/* Stores all cipher data that must persist between function calls */
struct chachapoly_ctx_mt {
	/*
	 * Next expected seqnr to read. This is written by the main thread to
	 * indicate that all older keystreams may be replaced. It's read by
	 * worker threads and by the main thread during a rekey.
	 */
	u_int seqnr;
	/* Prevent workers from reading seqnr while main is updating it */
	pthread_mutex_t seqnr_lock;

	/* The pregenerated keystreams */
	struct mt_keystream streams[NUMSTREAMS]; /* NUMSTREAMS == 32 */

	/* Thread identifiers */
	pthread_t tid[NUMTHREADS]; /* NUMTHREADS == 2 */
	/* Block threads from reading their identifiers too soon */
	pthread_mutex_t tid_lock;

	/*
	 * Written by the main thread during initialization to track whether
	 * this process is a fork, in which case worker threads will be missing
	 * and lock states cannot be guaranteed to be sane.
	 */
	pid_t mainpid;

	/* Indirect performance metric */
	u_int strikes;

	/*
	 * Used as a resting point for worker threads. The main thread
	 * broadcasts to this cond primarily to indicate that worker threads may
	 * have fresh work. It is not directly used as a cancellation point, but
	 * cancellation points are positioned immediately before and after this
	 * waiting point.
	 */
	pthread_cond_t cond;

	/* A buffer of zeros fed to EVP ciphers to get raw XOR keystreams. */
	u_char zeros[KEYSTREAMLEN]; /* KEYSTREAMLEN == 32768 */

	/* All nontrivial thread-specific data */
	struct threadData tds[NUMTHREADS]; /* NUMTHREADS == 2 */
};

/*
 * This is directly copied from cipher-chachapoly-libcrypto.c, because we need
 * to use an identical context struct in order for cipher.c to be able to call
 * the multithreaded and serial implementations interchangeably. The struct is
 * declared, but not defined, in the cipher-chachapoly.h header. A pointer to
 * the multithreaded context is stored in main_evp as OpenSSL app data which is
 * ignored by the serial implementation.
 */
struct chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

/*
 * Used by worker threads to generate keystreams.
 *
 * Uses OpenSSL's ChaCha20 EVP to pre-generate the keystreams for anticipated
 * packets. This function does not manage any locks, so be sure to manage the
 * locks before and after calling it. Most invocations are from worker threads,
 * so this function must be thread safe. The main thread also calls this
 * function during initialization to give the soon-to-be-spawned worker threads
 * a head start.
 *
 * @param ks The keystream struct in which the new keystream should be stored.
 * @param seqnr The SSH sequence number of the new keystream to generate.
 * @param td Structure containing initialized EVP contexts and related buffers.
 * @param zeros A buffer of zeros used to get a raw XOR keystream from OpenSSL.
 * @retval 0 The keystream was generated successfully
 * @retval -1 An OpenSSL error occurred
 */
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

	/* update the sequence number */
	ks->seqnr = seqnr;
	return 0;
}

/*
 * Used to cleanup thread data structures.
 * This function is safe to call as long as the threadData was at least
 * partially initialized.
 *
 * @param td The thread data structure to be cleaned up.
 */
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


/*
 * Used to initialize a thread data structure so that it's ready to be used to
 * generate keystreams. This implementation is directly based on
 * cipher-chachapoly-libcrypto.c/chachapoly_new().
 * 
 * @param td The thread data structure to be initialized
 * @param ctx A cipher context from which EVP contexts will be cloned
 * @retval 0 The structure was initialized successfully
 * @retval -1 An OpenSSL error occurred and the structure was not initialized.
 */
int
initialize_threadData(struct threadData * td, struct chachapoly_ctx * ctx)
{
	memset(td,0,sizeof(*td));
	if ((td->main_evp = EVP_CIPHER_CTX_new()) == NULL ||
	    (td->header_evp = EVP_CIPHER_CTX_new()) == NULL)
		goto fail;
	if (!EVP_CIPHER_CTX_copy(td->main_evp, ctx->main_evp))
		goto fail;
	if (!EVP_CIPHER_CTX_copy(td->header_evp, ctx->header_evp))
		goto fail;
	/*
	 * Why isn't this check performed on main_evp, too? No idea, but the
	 * reference code in cipher-chachapoly-libcrypto.c doesn't do it either.
	 * Maybe it's a static value, so they'll always be the same?
	 */
	if (EVP_CIPHER_CTX_iv_length(td->header_evp) != 16)
		goto fail;
	/* td->seqnr will be set to the correct value by the worker thread */
	return 0;
 fail:
	free_threadData(td);
	return -1;
}

/*
 * Worker thread code. This loops until it receives a cancellation signal from
 * the main thread. It may exit early if it cannot find its thread ID in the
 * array written by the main thread.
 *
 * @param ctx_mt The shared multhreaded cipher context
 */
void
threadLoop (struct chachapoly_ctx_mt * ctx_mt)
{
	/* Will point to all of thread's nontrivial data */
	struct threadData * td;
	pthread_t self;
	int threadIndex = -1;
	
	/* Restrict cancellations to known points to maintain sanity of locks */
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

	/*
	 * Loop forever. If the thread is canceled, the thread terminates
	 * immediately WITHOUT "breaking" the loop. Code after the while loop
	 * never runs.
	 */
	while (1) {
		/*
		 * This is mostly just textbook pthread_cond_wait(), used to
		 * wait for ctx_mt->seqnr to change. Once the main thread
		 * changes ctx_mt->seqnr, it broadcasts to ctx_mt->cond, which
		 * triggers all threads which were waiting at ctx_mt->cond to
		 * proceed. The threads check to see if ctx_mt->seqnr REALLY
		 * changed (hypothetically, ctx_mt->cond could be erroneously
		 * triggered), and if so, proceed to scan the keystreams for new
		 * work.
		 *
		 * If a thread is canceled while it's holding seqnr_lock, it
		 * must free that lock before terminating, so a cleanup handler
		 * is registered using pthread_cleanup_push(...) and later
		 * deregistered using pthread_cleanup_pop(0).
		 *
		 * By restricting cancellations to two carefully chosen points,
		 * we can ensure that the locks will be in a known state when
		 * the thread cancels, and so we can release them appropriately.
		 */
		pthread_mutex_lock(&(ctx_mt->seqnr_lock));
		pthread_cleanup_push((void (*)(void *)) pthread_mutex_unlock,
		    &(ctx_mt->seqnr_lock));
		while (td->seqnr == ctx_mt->seqnr) {
			/* Briefly allow cancellations here. */
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
			pthread_testcancel();
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			/*
			 * Definitely disallow cancellations DURING the
			 * cond_wait, otherwise it becomes impossible to
			 * destroy the locks using standard pthread calls.
			 */
			/* Wait for main to update seqnr and signal us. */
			pthread_cond_wait(&(ctx_mt->cond),
			    &(ctx_mt->seqnr_lock));
			/* Briefly allow cancellations again. */
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
			pthread_testcancel();
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		}
		pthread_cleanup_pop(0);
		/*
		 * The main thread changed ctx_mt->seqnr, and we
		 * noticed, so update our internal value and move on.
		 */
		td->seqnr = ctx_mt->seqnr;
		pthread_mutex_unlock(&(ctx_mt->seqnr_lock));

		/*
		 * Check all of the keystreams that are this thread's
		 * responsibility, which is only every nth keystream, where n is
		 * the number of threads.
		 */
		for (int i=threadIndex; i<NUMSTREAMS; i+=NUMTHREADS) {
			struct mt_keystream * ks = &(ctx_mt->streams[i]);
			/* Skip over this keystream if it's not outdated. */
			if (ks->seqnr >= td->seqnr)
				continue;

			/* Prevent reading by the main thread */
			pthread_mutex_lock(&(ks->lock));
			/*
			 * This is just some math to get the next seqnr (which
			 * is greater than or equal to the current seqnr) for
			 * this index in the stream array.
			 */
			int seqnrStreamIndex = td->seqnr % NUMSTREAMS;
			u_int new_seqnr = td->seqnr + i - seqnrStreamIndex +
			    (i < seqnrStreamIndex ? NUMSTREAMS : 0);
			/* Generate the new keystream! */
			generate_keystream(ks, new_seqnr, td, ctx_mt->zeros);
			pthread_mutex_unlock(&(ks->lock));
		}
	}
	/* This will never happen. */
	return;
}

/*
 * Frees all data associated with the multithreaded context and cancels all the
 * worker threads. This function skips destroying the mutexes and conds, and
 * cancelling the threads if this process is not the one which initialized them,
 * which is an unavoidable potential memory leak.
 *
 * @param ctx_mt The multithreaded cipher context to clean up.
 */
void
free_ctx_mt(struct chachapoly_ctx_mt * ctx_mt)
{
	if (ctx_mt == NULL)
		return;

	/*
	 * Only cleanup the threads and mutexes if we are the PID that
	 * initialized them! If we're a fork, the threads don't really exist,
	 * and the the mutexes (and cond) are in an unknown state, which can't
	 * be safely destroyed.
	 */
	if (getpid() == ctx_mt->mainpid) {
		/*
		debug2_f("<main thread: pid=%u, tid=%u, ptid=0x%lx>", getpid(),
		    gettid(),pthread_self());
		*/
		/*
		 * Acquire seqnr_lock, so that thread cancellations can be sent
		 * without risking race conditions near cond. We don't need to
		 * acquire tid_lock, since we're only reading, and the main
		 * thread is the only writer, which is us!
		 */
		pthread_mutex_lock(&(ctx_mt->seqnr_lock));
		for (int i=0; i<NUMTHREADS; i++)
			pthread_cancel(ctx_mt->tid[i]);
		pthread_mutex_unlock(&(ctx_mt->seqnr_lock));
		/*
		 * At this point, the only threads which might not cancel are
		 * the ones currently stuck on pthread_cond_wait(), so free them
		 * now. There's a cancellation point immediately after the
		 * cond_wait() to prevent them from starting new work.
		 */
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
		pthread_mutex_destroy(&(ctx_mt->seqnr_lock));
		pthread_cond_destroy(&(ctx_mt->cond));
		for (int i=0; i<NUMSTREAMS; i++) {
			pthread_mutex_destroy(&(ctx_mt->streams[i].lock));
		}
	}

	/* The threads are all dead, so cleanup their data structures. */
	for (int i=0; i<NUMTHREADS; i++)
		free_threadData(&(ctx_mt->tds[i]));

	/* Zero and free the whole multithreaded cipher context. */
	freezero(ctx_mt,sizeof(*ctx_mt));
}

/*
 * Initialize a new multithreaded cipher context. This also pregenerates the
 * initial keystreams (serially) to give worker threads a head start, but as a
 * consequence, initialization is hypothetically slow and rekeying is expensive.
 *
 * @param ctx A serial cipher context from which the EVP contexts will be cloned
 * @param startseqnr Starting sequence number for the pregenerated keystreams
 * @returns If successful, the new multithreaded cipher context, otherwise NULL
 */
struct chachapoly_ctx_mt *
initialize_ctx_mt(struct chachapoly_ctx * ctx, u_int startseqnr)
{
	struct chachapoly_ctx_mt * ctx_mt = xmalloc(sizeof(*ctx_mt));
	/*
	 * Start from a fresh slate so that uninitialized data can be recognized
	 * as zeros. UPDATE: TODO: this wasn't reliable for checking locks, so I
	 * reworked the failure procedures. We might not need this memset
	 * anymore.
	 */
	memset(ctx_mt, 0, sizeof(*ctx_mt));
	/* Initialize the sequence number. When rekeying, this won't be zero. */
	ctx_mt->seqnr = startseqnr;

	if (pthread_mutex_init(&(ctx_mt->seqnr_lock), NULL))
		goto failfree;
	for (int i=0; i<NUMSTREAMS; i++) {
		if (pthread_mutex_init(&(ctx_mt->streams[i].lock), NULL))
			goto failseqnr;
	}

	if (pthread_mutex_init(&(ctx_mt->tid_lock), NULL))
		goto failstreams;

	/* Start with zero strikes. */
	ctx_mt->strikes=0;

	if (pthread_cond_init(&(ctx_mt->cond), NULL))
		goto failtid;

	/* This is unnecessary because we already zeroed the whole struct. */
	/* memset(ctx_mt->zeros,0,sizeof(ctx_mt->zeros)); */
	
	for (int i=0; i<NUMTHREADS; i++)
		if (initialize_threadData(&(ctx_mt->tds[i]), ctx))
			goto failthreaddata;
	struct threadData * mainData;

#if NUMTHREADS == 0
	/* There are none to borrow, so initialize our own. */
	struct threadData td;
	if (initialize_threadData(&td, ctx))
		goto failthreaddata;
	mainData = &td;
#else
	/* Borrow ctx_mt->tds[0] to do initial keystream generation. */
	mainData = &(ctx_mt->tds[0]);
#endif

	for (int i=0; i<NUMSTREAMS; i++) {
		int seqnrStreamIndex = startseqnr%NUMSTREAMS;
		u_int new_seqnr = startseqnr + i - seqnrStreamIndex +
		    (i<seqnrStreamIndex ? NUMSTREAMS : 0);
		if (generate_keystream(&(ctx_mt->streams[i]), new_seqnr,
		    mainData, ctx_mt->zeros))
			goto failstreamdata;
	}

#if NUMTHREADS == 0
	free_threadData(&td);
#endif

	/* Spawn threads. */

	/* Store the PID so that in the future, we can tell if we're a fork */
	ctx_mt->mainpid = getpid();
	int ret=0;
	/* Block workers from reading their thread IDs before we set them. */
	pthread_mutex_lock(&(ctx_mt->tid_lock));
	debug2_f("<main thread: pid=%u, tid=%u, ptid=0x%lx>", getpid(),
	    gettid(), pthread_self());
	for (int i=0; i<NUMTHREADS; i++) {
		/*
		 * If we fail to generate some threads, the thread ID will
		 * remain zeroed, which is unlikely to ever match a real thread,
		 * and so SHOULD be ignored by pthread_cancel and pthread_join
		 * while ctx_mt is being freed.
		 */
		if (pthread_create(&(ctx_mt->tid[i]), NULL,
		    (void * (*)(void *))threadLoop, ctx_mt)) {
			ret=1;
			break; /* No point in wasting time... */
		}
	}
	pthread_mutex_unlock(&(ctx_mt->tid_lock));
	if (ret) /* failed while starting a thread */
		goto failthreads;

	/* Success! */
	return ctx_mt;

 failthreads:
	free_ctx_mt(ctx_mt);
	return NULL; /* free_ctx_mt() takes care of everything below */
 failstreamdata:
 	/* FALLTHROUGH */
 failthreaddata:
	for (int i=0; i<NUMTHREADS; i++)
		free_threadData(&(ctx_mt->tds[i]));
 	/* FALLTHROUGH */
/* failcond: */
	pthread_cond_destroy(&(ctx_mt->cond));
 	/* FALLTHROUGH */
 failtid:
	pthread_mutex_destroy(&(ctx_mt->tid_lock));
 	/* FALLTHROUGH */
 failstreams:
	for (int i=0; i<NUMSTREAMS; i++)
		pthread_mutex_destroy(&(ctx_mt->streams[i].lock));
 	/* FALLTHROUGH */
 failseqnr:
	pthread_mutex_destroy(&(ctx_mt->seqnr_lock));
 	/* FALLTHROUGH */
 failfree:
	freezero(ctx_mt, sizeof(*ctx_mt));
	return NULL;
}

/*
 * Initializes an MT context and binds it to the existing serial context. It
 * somewhat redundantly returns the MT context after adding it to the serial
 * context. This avoids requiring the calling thread to make another EVP call
 * to get the MT context we just created.
 *
 * @param ctx The serial cipher context to which the MT context will be bound
 * @param startseqnr Starting sequence number for the pregenerated keystreams
 * @returns If successful, the new multithreaded cipher context, otherwise NULL
 */
struct chachapoly_ctx_mt *
add_mt_to_ctx(struct chachapoly_ctx * ctx,u_int startseqnr)
{
	if (ctx == NULL)
		return NULL;
	struct chachapoly_ctx_mt * ctx_mt = initialize_ctx_mt(ctx, startseqnr);
	/* Don't touch the serial context if we're failing. */
	if (ctx_mt == NULL)
		return NULL;
	EVP_CIPHER_CTX_set_app_data(ctx->main_evp, ctx_mt);
	return ctx_mt;
}

/*
 * Retrieve MT context from serial context
 *
 * @param ctx The serial cipher context containing the MT context
 * @returns The bound MT context if there is one, otherwise NULL.
 */
struct chachapoly_ctx_mt *
get_ctx_mt(struct chachapoly_ctx * ctx)
{
	struct chachapoly_ctx_mt * ctx_mt;

	if (ctx == NULL)
		return NULL;
	ctx_mt = EVP_CIPHER_CTX_get_app_data(ctx->main_evp);
	return ctx_mt;
}

/*
 * Initialize a new serial-implementation-compatible cipher context, including
 * an embedded multithreaded context. Keystreams will be pre-generated starting
 * at the sequence number read from the previous context (passed via oldctx), or
 * starting at sequence number zero if the previous context is NULL or otherwise
 * cannot be read. The provided key should be 64-bytes long, in which the first
 * half will be used for the main ChaCha20 instance, and the second half will be
 * used for a secondary ChaCha20 instance used to encrypt header informtation.
 *
 * TODO: If it fails, should it try to return a serial context instead?
 * (right now it does not)
 *
 * @param oldctx The (un-freed) previous context, for use when rekeying, or NULL
 * @param key 64-byte cipher encryption/decryption key
 * @param keylen Passed to chachapoly_new() for generation of the serial context
 * @returns If successful, the new cipher context, otherwise NULL
 */
struct chachapoly_ctx *
chachapoly_new_mt(struct chachapoly_ctx * oldctx, const u_char * key,
    u_int keylen)
{
	struct chachapoly_ctx *ctx = chachapoly_new(key, keylen);
	if (ctx == NULL)
		return NULL;

	/*
	 * If we're not rekeying, 0 is a good choice, since we're presumably
	 * close to the beginning anyway. Small differences between zero and the
	 * true sequence number will lead to small amounts of wasted effort. For
	 * large differences, the wasted effort is capped by the number of
	 * keystreams being pre-generated.
	 */
	u_int startseqnr = 0;

	if (oldctx != NULL) { /* Rekeying, so get the old sequence number. */
		/* Only MT contexts store seqnr, so look for one */
		struct chachapoly_ctx_mt * oldctx_mt = get_ctx_mt(oldctx);
		if (oldctx_mt != NULL)
			/* Only reading, so no need to lock */
			startseqnr=oldctx_mt->seqnr;

		/* Don't do this! It's not our job! */
		/* chachapoly_free_mt(oldctx); */
	}

	struct chachapoly_ctx_mt * ctx_mt = initialize_ctx_mt(ctx, startseqnr);
	explicit_bzero(&startseqnr, sizeof(startseqnr));

	if (ctx_mt == NULL) {
		chachapoly_free(ctx);
		return NULL;
	}
	EVP_CIPHER_CTX_set_app_data(ctx->main_evp, ctx_mt);
	return ctx;
}

/*
 * Clean up a cipher context. This function frees both the provided serial
 * cipher context and any embedded multithreaded cipher contextx which might
 * also be present.
 *
 * @param cpctx The cipher context which needs to be cleaned up.
 */
void
chachapoly_free_mt(struct chachapoly_ctx *cpctx)
{
	if (cpctx == NULL)
		return;
	struct chachapoly_ctx_mt * ctx_mt = get_ctx_mt(cpctx);
	free_ctx_mt(ctx_mt); /* Safe even if ctx_mt == NULL */
	/* This is probably unnecessary, but should be harmless. */
	EVP_CIPHER_CTX_set_app_data(cpctx->main_evp, NULL);
	chachapoly_free(cpctx);
}

/*
 * Encrypt or decrypt an SSH packet. Uses the header key (the second half of the
 * key provided during initialization) to encrypt or decrypt 'aadlen' bytes from
 * 'src', storing the result in 'dest'. These encrypted header bytes are treated
 * as additional authenticated data for poly1305 MAC calculation. Next it
 * encrypts or decrypts 'len' bytes at offset 'aadlen' from 'src', and stores
 * it at the same offset in 'dest'. The authentication tag is read from (and
 * verified) or written to POLY1305_TAGLEN bytes at offset 'len'+'aadlen'.
 *
 * If called without an MT context, this creates one, which is slow. If creation
 * fails, it falls back to using the serial implementation of the crypt()
 * function. TODO: is this what we want it to do?
 *
 * If this function is called from a child process that has forked from a parent
 * which previously initialized a multithreaded cipher context, then we clean up
 * the original MT context and initialize a new one.
 *
 * @param ctx a cipher context which may or may not have a bound MT context.
 * @param seqnr the SSH sequence number, used to lookup the correct keystream
 * @param dest the encrypted/decrypted output range
 * @param src the unencrypted/undecrypted input range
 * @param len the length of the packet payload (in bytes)
 * @param aadlen the packet header length (in bytes)
 * @param authlen the authentication tag length (in bytes)
 * @param do_encrypt set to 1 to encrypt, 0 to decrypt
 * @retval 0 Encryption or decryption was successful
 * @retval SSH_ERR_MAC_INVALID Poly1305 MAC verification failed
 * @retval SSH_ERR_LIBCRYPTO_ERROR Serial fallback failed with an OpenSSL error.
 * @retval SSH_ERR_INTERNAL_ERROR An unknown error occurred.
 */
int
chachapoly_crypt_mt(struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
	/* debug3_f("<debug> seqnr == %u%c",seqnr,do_encrypt ? 'e' : 'd'); */
	struct chachapoly_ctx_mt * ctx_mt = get_ctx_mt(ctx);
	/* If initialized as a serial context, generate the MT context */
	if (ctx_mt == NULL) {
		/* TODO: compiler hint that this is unlikely */
		ctx_mt = add_mt_to_ctx(ctx, seqnr);
		if (ctx_mt == NULL) {
			debug_f(
			    "Failed to upgrade to a multithreaded context.");
			return chachapoly_crypt(ctx, seqnr, dest, src, len,
			    aadlen, authlen, do_encrypt);
		}
	} else if (ctx_mt->mainpid != getpid()) { /* we're a fork */
		/*
		 * TODO: this is EXTREMELY RARE, may never happen at all (only
		 * if the fork calls crypt), so we should tell the compiler.
		 */
		/* The worker threads don't exist, so regenerate ctx_mt */
		free_ctx_mt(ctx_mt);
		EVP_CIPHER_CTX_set_app_data(ctx->main_evp, NULL);
		ctx_mt = add_mt_to_ctx(ctx, seqnr);
	}

	/* The sequence number read from the pregenerated keystream */
	u_int found_seqnr;

	/* Convenience pointer to the desired keystream's slot */
	struct mt_keystream * ks = &(ctx_mt->streams[seqnr % NUMSTREAMS]);
	/* Return value, to reproduce the serial implementation behavior. */
	int r = SSH_ERR_INTERNAL_ERROR;
	/*
	 * Block if a worker is currently generating the data. If trylock() is
	 * nonzero, then a worker is currently busy with the data, so increment
	 * the strikes and then block. If trylock() is zero, then the lock has
	 * been obtained, so proceed.
	 */
	if (pthread_mutex_trylock(&(ks->lock))) {
		ctx_mt->strikes++;
		debug_f("Caught up to workers! Strike %u! Waiting.",
		    ctx_mt->strikes);
		pthread_mutex_lock(&(ks->lock));
	}
	/* Read the sequence number of the keystream in slot */
	found_seqnr = ks->seqnr;
	/* Don't hold the lock. Workers won't touch it until we signal them. */
	pthread_mutex_unlock(&(ks->lock));

	/* TODO: add compiler hint that this is likely */
	if (found_seqnr == seqnr) { /* Good, it's the correct keystream. */
		explicit_bzero(&found_seqnr, sizeof(found_seqnr));
		/* check tag before anything else */
		if (!do_encrypt) {
			const u_char *tag = src + aadlen + len;
			u_char expected_tag[POLY1305_TAGLEN];
			poly1305_auth(expected_tag, src, aadlen + len,
			    ks->poly_key);
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
			for (u_int i=0; i<len; i++)
				dest[aadlen+i] = ks->mainStream[i] ^
				    src[aadlen+i];
			/* calculate and append tag */
			if (do_encrypt)
				poly1305_auth(dest+aadlen+len, dest, aadlen+len,
				    ks->poly_key);
			r=0; /* Success! */
		}
		if (r) /* Anything nonzero is an error. */
			return r;

		/* Prevent workers from reading seqnr while we increment it */
		pthread_mutex_lock(&(ctx_mt->seqnr_lock));
		/* All keystreams older than seqnr + 1 are outdated */
		ctx_mt->seqnr = seqnr + 1; /* Will be read by workers */
		pthread_mutex_unlock(&(ctx_mt->seqnr_lock));
		/* Signal worker threads to scan the keystreams for new work */
		pthread_cond_broadcast(&(ctx_mt->cond));
		return 0;
	} else { /* Bad, it's the wrong keystream. */
		/*
		 * The keystream is either too old or completely wrong. Either
		 * way, we update the sequence number in the context and signal
		 * the workers to build fresh keystreams.
		 */
		ctx_mt->strikes++;
		debug_f( "Cache miss! Seeking %u, found %u. Strike %u! "
		    "Falling back to serial mode.", seqnr, found_seqnr,
		    ctx_mt->strikes);
		explicit_bzero(&found_seqnr, sizeof(found_seqnr));
		/* Same logic as above */
		pthread_mutex_lock(&(ctx_mt->seqnr_lock));
		ctx_mt->seqnr = seqnr+1;
		pthread_mutex_unlock(&(ctx_mt->seqnr_lock));
		pthread_cond_broadcast(&(ctx_mt->cond));

		/* Fall back to the serial implementation. */
		return chachapoly_crypt(ctx, seqnr, dest, src, len, aadlen,
		    authlen, do_encrypt);
	}
}

/*
 * Decrypt and extract the encrypted packet length. Based on the implementation
 * from "cipher-chachapoly-libcrypto.c". Falls back to the serial implementation
 * if there's no multithreaded cipher context, if we've forked since the
 * multithreaded cipher context was initialized, or if the pregenerated
 * keystream in the corresponding slot does not match the sequence number given
 * as a parameter.
 *
 * @param ctx The cipher context to use for decryption
 * @param plenp The address into which the packet length should be stored
 * @param seqnr The sequence number of the packet (needed for decryption)
 * @param cp The encrypted packet ciphertext
 * @param len The length of the encrypted header containing the packet length
 * @retval 0 The packet length was decrypted successfully.
 * @retval SSH_ERR_MESSAGE_INCOMPLETE The packet header given is too short.
 * @retval SSH_ERR_LIBCRYPTO_ERROR Serial fallback failed with an OpenSSL error.
 */
int
chachapoly_get_length_mt(struct chachapoly_ctx *ctx, u_int *plenp, u_int seqnr,
    const u_char *cp, u_int len)
{
	struct chachapoly_ctx_mt * ctx_mt = get_ctx_mt(ctx);
	/* TODO: add compiler hints */
	if (ctx_mt == NULL) { /* Don't bother upgrading to MT just for this. */
		debug_f("No MT context. Falling back to serial mode.");
		return chachapoly_get_length(ctx, plenp, seqnr, cp, len);
	}

	if (ctx_mt->mainpid != getpid()) { /* Use serial mode if we're a fork */
		debug_f("We're a fork. Falling back to serial mode.");
		return chachapoly_get_length(ctx, plenp, seqnr, cp, len);
	}

	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;

	u_char buf[4];
	u_int found_seqnr;
	struct mt_keystream * ks = &(ctx_mt->streams[seqnr % NUMSTREAMS]);
	if (pthread_mutex_trylock(&(ks->lock))) {
		ctx_mt->strikes++;
		debug_f("Caught up to workers! Strike %u! Waiting.",
		    ctx_mt->strikes);
		pthread_mutex_lock(&(ks->lock));
	}
	found_seqnr = ks->seqnr;
	pthread_mutex_unlock(&(ks->lock));

	if (found_seqnr == seqnr) {
		explicit_bzero(&found_seqnr, sizeof(found_seqnr));
		for (u_int i=0; i < sizeof(buf); i++)
			buf[i]=ks->headerStream[i] ^ cp[i];
		*plenp = PEEK_U32(buf);
		return 0;
	} else {
		ctx_mt->strikes++;
		debug_f("Cache miss! Seeking %u, found %u. Strike %u! "
		    "Falling back to serial mode.", seqnr, found_seqnr,
		    ctx_mt->strikes);
		explicit_bzero(&found_seqnr, sizeof(found_seqnr));
		return chachapoly_get_length(ctx, plenp, seqnr, cp, len);
	}
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
