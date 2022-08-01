// The includes were mostly copied from cipher-chachapoly-libcrypto.c
// TODO: audit includes

#include "includes.h"
#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"
#endif

#if defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include <openssl/evp.h>

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"

#include "xmalloc.h"
#include "pthread.h"
#include "cipher-chachapoly.h"
#include "cipher-chachapoly-libcrypto-mt.h"

/* Size of keystream to pregenerate, measured in bytes */
/* It should at least be as large as the maximum SSH packet size (32768 bytes),
 * and there is no benefit to using a larger size than necessary. It must be a
 * multiple of CHACHA_BLOCKLEN (64 bytes). */
/* TODO: If there is a constant defining the maximum packet size, then this
 * does not need to be tunable. */
#define KEYSTREAMLEN 32768

/* Number of worker threads to spawn */
/* TODO: This is temporarily hardcoded, and will be replaced with MAXTHREADS and
 * a dynamic value. The total number of threads will be at least
 * 1 + 2*NUMTHREADS, to account for the main thread and NUMTHREADS each for
 * sending and receiving data on one channel.*/
#define NUMTHREADS 2

/* Total size of the keystream cache, measured in bytes */
/* This is the most significant contribution to the memory footprint of this
 * multithreaded cipher. The total memory impact will be twice this value, to
 * account for sending and receiving. This must be a multiple of KEYSTREAMLEN.
 */
#define TOTALCACHE 1048576

/* When this value is exceeded, spawn a new worker thread. Not implemented. */
#define MAXSTRIKES 3

// all members are written by worker threads, read by main thread
struct mt_keystream {
    u_char poly_key[POLY1305_KEYLEN]; // POLY1305_KEYLEN == 32
    u_char headerStream[CHACHA_BLOCKLEN]; // CHACHA_BLOCKLEN == 64
    u_char mainStream[KEYSTREAMLEN]; // KEYSTREAMLEN == 32768

    // Allow main thread to verify that the keystream was generated for the
    // expected seqnr. Also allow worker threads to see if the keystream is old.
    u_int seqnr;

    // Make sure main thread doesn't read while worker threads are still writing
    // No need to worry about worker threads writing too soon
    pthread_mutex_t lock;
};

struct threadData {
    // used in generate_keystream():
    EVP_CIPHER_CTX * main_evp;
    EVP_CIPHER_CTX * header_evp;
    u_char seqbuf[16];

    // used in threadLoop:
    u_int seqnr;
};

#define NUMSTREAMS (TOTALCACHE/KEYSTREAMLEN)
struct chachapoly_ctx_mt {
    // next expected seqnr to read (safe to replace older keystreams)
    // written by main thread, read by worker threads
    u_int seqnr;
    pthread_mutex_t seqnr_lock;
    
    // written by workers, read by main thread
    struct mt_keystream streams[NUMSTREAMS]; // NUMSTREAMS == 32

    // written by main thread, read by worker threads
    pthread_t tid[NUMTHREADS];
    pthread_mutex_t tid_lock;

    // written by main thread during initialization
    // used to determine whether we've forked
    pid_t mainpid;

    // only used by main thread
    u_int strikes;

    // triggered by main thread, encountered by worker threads
    // used to tell worker threads there might be fresh work to do
    // also used as a safe point for threads to exit via cancellation
    pthread_cond_t cond;
   
    // buffer of zeros fed to EVP ciphers to get keystreams
    u_char zeros[KEYSTREAMLEN];

    // all thread-specific data
    struct threadData tds[NUMTHREADS];
};

// Needed because the main_evp and header_evp members are not exposed in the
// header file. This needs to be identical to the definition in
// cipher-chachapoly-libcrypto.c
struct chachapoly_ctx {
    EVP_CIPHER_CTX *main_evp, *header_evp;
};

// Manage locks before calling generate_keystream()!
// Returns -1 on error, 0 on success
// Called by worker threads (in a loop) and the main thread during init.
int
generate_keystream(struct mt_keystream * ks,u_int seqnr,struct threadData * td,u_char * zeros) {
    debug3_f("<debug> seqnr = %u",seqnr);
    //generate poly1305 key
    memset(td->seqbuf,0,sizeof(td->seqbuf));
    POKE_U64(td->seqbuf + 8, seqnr);
    memset(ks->poly_key,0,sizeof(ks->poly_key));
    if(!EVP_CipherInit(td->main_evp,NULL,NULL,td->seqbuf,1) ||
        EVP_Cipher(td->main_evp,ks->poly_key,
        ks->poly_key,sizeof(ks->poly_key))<0) {
        return -1;
    }

    //generate header keystream for encrypting payload length
    if(!EVP_CipherInit(td->header_evp,NULL,NULL,td->seqbuf,1) ||
        EVP_Cipher(td->header_evp,ks->headerStream,
        zeros,CHACHA_BLOCKLEN)<0) {
        return -1;
    }

    //generate main keystream for encrypting payload
    td->seqbuf[0] = 1;
    if (!EVP_CipherInit(td->main_evp,NULL,NULL,td->seqbuf,1) ||
        EVP_Cipher(td->main_evp,ks->mainStream,zeros,KEYSTREAMLEN)<0) {
        return -1;
    }

    //update the sequence number
    ks->seqnr = seqnr;
    debug3_f("<return good> seqnr = %u",seqnr);
    return 0;
}

// Safe to call as long as the threadData was (at least partially) initialized.
void
free_threadData(struct threadData * td) {
    debug3_f("<debug>");
    if(td == NULL)
        return;
    if(td->main_evp) // false if initialization didn't get this far
        EVP_CIPHER_CTX_free(td->main_evp);
    if(td->header_evp) // false if initialization didn't get this far
        EVP_CIPHER_CTX_free(td->header_evp);
    explicit_bzero(td,sizeof(*td));
    debug3_f("<return>");
}


// Based on cipher-chachapoly-libcrypto.c/chachapoly_new()
// Returns -1 on error, 0 on success
// Called my the main thread during initialization
int
initialize_threadData(struct threadData * td, const u_char mainkey[CHACHA_KEYLEN], const u_char headerkey[CHACHA_KEYLEN]) {
    debug3_f("<debug>");
    memset(td,0,sizeof(*td));
    if((td->main_evp = EVP_CIPHER_CTX_new()) == NULL ||
        (td->header_evp = EVP_CIPHER_CTX_new()) == NULL)
        goto fail;
    if(!EVP_CipherInit(td->main_evp,EVP_chacha20(),mainkey,NULL,1))
        goto fail;
    if(!EVP_CipherInit(td->header_evp,EVP_chacha20(),headerkey,NULL,1))
        goto fail;
    // Why isn't this check performed on main_evp, too? No idea, but the
    // reference code in cipher-chachapoly-libcrypto.c doesn't do it either.
    // Maybe it's a static value, so they'll always be the same?
    if(EVP_CIPHER_CTX_iv_length(td->header_evp) != 16)
        goto fail;
    memset(td->seqbuf,0,sizeof(td->seqbuf));
    // seqnr==0 CAN be a real seqnr (I think?). It's good starting bet if the
    // sequence number is unknown.
    td->seqnr = 0;
    debug3_f("<return good>");
    return 0;
 fail:
    free_threadData(td); // this is safe any time after memset
    return -1;
}

// Just to avoid more function signature warnings
void unlock(void * lock) {
    pthread_mutex_unlock(lock);
}

// Return value is unused, just set to (void *) for the function signature.
void * threadLoop (void * vctx_mt) {
    debug3_f("<debug>");

    // Pointless cast to avoid warnings caused by the function signature.
    // When spawning threads, the argument is expected to be (void *).
    struct chachapoly_ctx_mt * ctx_mt = vctx_mt;

    // Initialize to an impossible number to enable error checking
    int threadIndex = NUMTHREADS;
    // Will point to all of thread's nontrivial data
    struct threadData * td;

    // Wait for main thread to fill in thread IDs.
    // The main thread won't release the lock until it's safe to proceed.
    pthread_mutex_lock(&(ctx_mt->tid_lock));
    // We don't need to hold the lock for any reason.
    // TODO: Maybe there's a way to block on a lock, without acquiring it?
    pthread_mutex_unlock(&(ctx_mt->tid_lock));

    for(int i=0; i<NUMTHREADS; i++) { // Get thread ID
        if(pthread_equal(ctx_mt->tid[i],pthread_self())) {
            threadIndex=i;
            break;
        }
    }
    if(threadIndex == NUMTHREADS) { // the for-loop completed without matching
        debug_f("Thread ID not found! Exiting!");
        return NULL;
    }
    debug2_f("internal tid: %d, external tid: %u",threadIndex,gettid());

    // Now that we have the thread ID, grab the thread data.
    td = &(ctx_mt->tds[threadIndex]);

    // Loop forever. If the thread is canceled, the thread terminates
    // immediately WITHOUT "breaking" the loop. Code after the while loop never
    // runs.
    debug2_f("Thread starting loop. pid=%u, tid=%u, ptid=0x%lx",getpid(),gettid(),pthread_self());
    while(1) {
        debug3_f("<loop %d>",threadIndex);
        // This is mostly just textbook pthread_cond_wait()
        // This is used to wait for ctx_mt->seqnr to change. Once the main
        // thread changes ctx_mt->seqnr, it broadcasts to ctx_mt->cond, which
        // triggers all threads which were waiting at ctx_mt->cond to proceed
        // by checking to see if ctx_mt->seqnr REALLY changed (hypothetically,
        // ctx_mt->cond could be erroneously triggered), and if so, proceed
        // with another execution of the while loop.
        pthread_mutex_lock(&(ctx_mt->seqnr_lock)); {
            while(td->seqnr == ctx_mt->seqnr) {
                debug3_f("<cond_loop %d>",threadIndex);
                // If we've been canceled, this tells the thread to release
                // ctx_mt->seqnr_lock while exiting.
                pthread_cleanup_push(unlock,&(ctx_mt->seqnr_lock));
                // Specifically offer to cancel here
                pthread_testcancel();
                // Don't actually allow cancellations DURING the cond_wait.
                pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL);
                // Wait for main to read a keystream and update seqnr
                pthread_cond_wait(&(ctx_mt->cond),&(ctx_mt->seqnr_lock));
                // Allow cancellations again
                pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);
                // Specifically offer to cancel here
                pthread_testcancel();
                // If we get this far, we'll be able to release the lock on
                // ctx_mt->seqnr_lock ourselves.
                pthread_cleanup_pop(0);
            }
            // The main thread changed ctx_mt->seqnr, and we noticed, so update
            // our internal value and move on.
            td->seqnr = ctx_mt->seqnr;
        } pthread_mutex_unlock(&(ctx_mt->seqnr_lock));

        // Check all of the keystreams that are this thread's responsibility,
        // which is only every nth keystream, where n is the number of threads.
        for(int i=threadIndex; i<NUMSTREAMS; i+=NUMTHREADS) {
            // Only generate a new keystream if the selected keystream is old.
            if(ctx_mt->streams[i].seqnr < td->seqnr) {
                // Lock the keystream here, so that the main thread knows we're
                // updating it.
                pthread_mutex_lock(&(ctx_mt->streams[i].lock)); {
                    // This is just some math to get the next seqnr (which is
                    // greater than or equal to the current seqnr) for this
                    // index in the stream array.
                    int seqnrStreamIndex = td->seqnr % NUMSTREAMS;
                    u_int new_seqnr = td->seqnr + i - seqnrStreamIndex
                        + (i<seqnrStreamIndex ? NUMSTREAMS : 0);
                    // If we're somehow canceled during the keystream
                    // generation, we'll need to release the lock.
                    pthread_cleanup_push(unlock,&(ctx_mt->streams[i].lock));
                    // Actually generate the new keystream!
                    generate_keystream(&(ctx_mt->streams[i]),new_seqnr,td,ctx_mt->zeros);
                    // Now we can release the lock ourselves.
                    pthread_cleanup_pop(0);
                } pthread_mutex_unlock(&(ctx_mt->streams[i].lock));
            }
        }
    }

    debug_f("Thread %02d exited in an unpredicted way. This shouldn't happen!",threadIndex);

    return NULL;
}

// Safe to call as long as all the locks and conds have been initialized
// Skips the mutexes, conds, and thread-killing if this process is not the one
// which initialized them. Potential memory leak, but I don't think we can do
// anything about it.
void
free_ctx_mt(struct chachapoly_ctx_mt * ctx_mt) {
    debug3_f("<debug>");
    if(ctx_mt == NULL)
        return;
    
    // Only cleanup the threads and mutexes if we are the PID that initialized
    // them! If we're a fork, the threads don't really exist, and the the
    // mutexes (and cond) are in an unknown state, which can't be safely
    // destroyed.
    if(getpid() == ctx_mt->mainpid) {
        // Kill threads and free per-thread data
        // Send cancellations
        // Get seqnr_lock first, to prevent race conditions involving cond
        // Don't need to acquire the tid_lock, since we're only reading, and
        // the main thread is the only writer, which is us!
        debug2_f("<main thread: pid=%u, tid=%u, ptid=0x%lx>",getpid(),gettid(),pthread_self());
        pthread_mutex_lock(&(ctx_mt->seqnr_lock)); {
            for(int i=0; i<NUMTHREADS; i++)
                pthread_cancel(ctx_mt->tid[i]);
        } pthread_mutex_unlock(&(ctx_mt->seqnr_lock));
        //At this point, the only threads which might not cancel are the ones
        //currently stuck on pthread_cond_wait(), so free them now. There's a
        //cancellation point immediately after the cond_wait(), so there's no
        //need to worry about them starting more work.
        pthread_cond_broadcast(&(ctx_mt->cond));
        for(int i=0; i<NUMTHREADS; i++) {
            debug2_f("Joining %d: %lx",i,ctx_mt->tid[i]);
            //If the thread was already idle, this won't block. Busy threads
            //will encounter a cancellation point when they finish their work.
            pthread_join(ctx_mt->tid[i],NULL);
            debug2_f("Joined %d",i);
        }
        pthread_mutex_destroy(&(ctx_mt->tid_lock));
        pthread_mutex_destroy(&(ctx_mt->seqnr_lock));
        pthread_cond_destroy(&(ctx_mt->cond));
  
        //Stream data will get erased by freezero later.
        for(int i=0; i<NUMSTREAMS; i++) {
            pthread_mutex_destroy(&(ctx_mt->streams[i].lock));
        }
    }

    //The threads are all dead, so we can cleanup their data.
    for(int i=0; i<NUMTHREADS; i++)
        free_threadData(&(ctx_mt->tds[i]));

    //Zero and free
    freezero(ctx_mt,sizeof(*ctx_mt));
    debug3_f("<return>");
}

// This pregenerates the initial keystreams (serially) to give worker threads a
// head start, but as a consequence, initialization is hypothetically slow, and
// rekeying is expensive.
struct chachapoly_ctx_mt *
initialize_ctx_mt(const u_char mainkey[CHACHA_KEYLEN], const u_char headerkey[CHACHA_KEYLEN], u_int startseqnr) {
    debug3_f("<debug>");
    struct chachapoly_ctx_mt * ctx_mt = xmalloc(sizeof(*ctx_mt));
    // Start from a fresh slate so that uninitialized data can be recognized as
    // zeros. UPDATE: TODO: this wasn't reliable for checking locks, so I
    // reworked the failure procedures. We might not need this memset anymore.
    memset(ctx_mt,0,sizeof(*ctx_mt));
    // Initialize the sequence number. When rekeying, this won't be zero.
    ctx_mt->seqnr = startseqnr;

    if(pthread_mutex_init(&(ctx_mt->seqnr_lock),NULL))
        goto failfree;
/*    for(int i=0; i<CHACHA_KEYLEN; i++) {
        ctx_mt->mainkey[i]=mainkey[i];
        ctx_mt->headerkey[i]=headerkey[i];
    }*/
    for(int i=0; i<NUMSTREAMS; i++) {
        if(pthread_mutex_init(&(ctx_mt->streams[i].lock),NULL))
            goto failseqnr;
    }

    if(pthread_mutex_init(&(ctx_mt->tid_lock),NULL))
        goto failstreams;

    // Start with zero strikes.
    ctx_mt->strikes=0;

    if(pthread_cond_init(&(ctx_mt->cond),NULL))
        goto failtid;

    // This is unnecessary because we already zeroed the whole struct.
    //memset(ctx_mt->zeros,0,sizeof(ctx_mt->zeros));
    
    for(int i=0; i<NUMTHREADS; i++) {
        if(initialize_threadData(&(ctx_mt->tds[i]),mainkey,headerkey))
            goto failthreaddata;
    }
#if NUMTHREADS > 0
    // Borrow ctx_mt->tds[0] to do initial keystream generation.
    for(int i=0; i<NUMSTREAMS; i++) {
        int seqnrStreamIndex = startseqnr%NUMSTREAMS;
        u_int new_seqnr = startseqnr+i-seqnrStreamIndex+(i<seqnrStreamIndex ? NUMSTREAMS : 0);
        if(generate_keystream(&(ctx_mt->streams[i]),new_seqnr,&(ctx_mt->tds[0]),ctx_mt->zeros))
            goto failstreamdata;
    }
#else
    struct threadData mainData;
    if(initialize_threadData(&mainData,mainkey,headerkey))
        goto failthreaddata;
    for(int i=0; i<NUMSTREAMS; i++) {
        int seqnrStreamIndex = startseqnr%NUMSTREAMS;
        u_int new_seqnr = startseqnr+i-seqnrStreamIndex+(i<seqnrStreamIndex ? NUMSTREAMS : 0);
        if(generate_keystream(&(ctx_mt->streams[i]),new_seqnr,&mainData,ctx_mt->zeros))
            goto failstreamdata;
    }
    free_threadData(&mainData);
#endif

    // Spawn threads.

    // Store the PID so that in the future, we can know whether we're a fork
    ctx_mt->mainpid = getpid();
    int ret=0;
    // Grab lock so that threads can't read their thread ID before we've set it.
    pthread_mutex_lock(&(ctx_mt->tid_lock)); {
        debug2_f("<main thread: pid=%u, tid=%u, ptid=0x%lx>",getpid(),gettid(),pthread_self());
        for(int i=0; i<NUMTHREADS; i++) {
            //If we fail to generate some threads, the thread ID will remain
            //zeroed, which is unlikely to ever match a real thread, and so will
            //be ignored by pthread_cancel and pthread_join while ctx_mt is
            //being freed.
            if(pthread_create(&(ctx_mt->tid[i]),NULL,threadLoop,ctx_mt)) {
                ret=1;
                break; // No point in wasting time...
            }
        }
    } pthread_mutex_unlock(&(ctx_mt->tid_lock));
    if(ret) // failed while starting a thread
        goto failthreads;

    // Success!
    debug3_f("<return good>");
    return ctx_mt;

 failthreads:
    free_ctx_mt(ctx_mt);
    debug_f("<return NULL (bad)>");
    return NULL; // free_ctx_mt() takes care of everything below
 failstreamdata:
 failthreaddata:
    for(int i=0; i<NUMTHREADS; i++)
        free_threadData(&(ctx_mt->tds[i]));
// failcond: // not used at the moment
    pthread_cond_destroy(&(ctx_mt->cond));
 failtid:
    pthread_mutex_destroy(&(ctx_mt->tid_lock));
 failstreams:
    for(int i=0; i<NUMSTREAMS; i++)
        pthread_mutex_destroy(&(ctx_mt->streams[i].lock));
 failseqnr:
    pthread_mutex_destroy(&(ctx_mt->seqnr_lock));
 failfree:
    freezero(ctx_mt,sizeof(*ctx_mt));
    debug_f("<return NULL (bad)>");
    return NULL;
}

// Initializes an MT context and binds it to the existing serial context.
// It somewhat redundantly returns the MT context after adding it to the serial
// context. This avoids requiring the calling thread to make another EVP call
// to get the MT context we just created.
struct chachapoly_ctx_mt *
add_mt_to_ctx(struct chachapoly_ctx * ctx,u_int startseqnr) {
    debug3_f("<debug>");
    if(ctx == NULL)
        return NULL;
    //TODO: this is a hack! It abuses undocumented OpenSSL structure definitions
    u_char * cipherDataM = EVP_CIPHER_CTX_get_cipher_data(ctx->main_evp);
    u_char * cipherDataH = EVP_CIPHER_CTX_get_cipher_data(ctx->header_evp);
    struct chachapoly_ctx_mt * ctx_mt = initialize_ctx_mt(cipherDataM,cipherDataH,startseqnr);
    if(ctx_mt == NULL)
        return NULL;
    EVP_CIPHER_CTX_set_app_data(ctx->main_evp, ctx_mt);
    debug3_f("<return good>");
    return ctx_mt;
}

// Retrieve MT context from serial context
// Returns NULL if there is no MT context
struct chachapoly_ctx_mt *
get_ctx_mt(struct chachapoly_ctx * ctx) {
    debug3_f("<debug>");
    if(ctx == NULL)
        return NULL;
    struct chachapoly_ctx_mt * ctx_mt = EVP_CIPHER_CTX_get_app_data(ctx->main_evp);
    debug3_f("<return good>");
    return ctx_mt;
}

// If it fails, should it try to return a serial context instead?
// (right now it does not)
struct chachapoly_ctx *
chachapoly_new_mt(struct chachapoly_ctx * oldctx, const u_char *key, u_int keylen)
{
    debug3_f("<debug>");
	struct chachapoly_ctx *ctx = chachapoly_new(key,keylen);
    if(ctx == NULL) {
        debug3_f("<return NULL (bad)>");
        return NULL;
    }

    // If we're not rekeying, 0 is a good choice.
    u_int startseqnr = 0;

    if(oldctx != NULL) { // We are rekeying! Try to get the sequence number.
        debug_f("REKEY!!!");
        // Serial contexts don't store the sequence number, so check to see if
        // it has an MT context
        struct chachapoly_ctx_mt * oldctx_mt = get_ctx_mt(oldctx);
        if(oldctx_mt != NULL) {
            // The old context's threads could still be active, so lock the
            // seqnr before reading it. It's OK if the seqnr is a little bit out
            // of date, it just means some work will be wasted. The first
            // crypt() call will correct the seqnr, but it's better if starts at
            // least close.
            // If we've forked from the process that initialized oldctx_mt, we
            // don't have to worry about the locks because only main writes the
            // seqnr, which can't happen while main is forking. If the mutex
            // DOES happen to be locked, we'd deadlock anyway, since there are
            // no threads which can release it.
            if(getpid() == oldctx_mt->mainpid) { // we're not a fork
                pthread_mutex_lock(&(oldctx_mt->seqnr_lock)); {
                    startseqnr=oldctx_mt->seqnr;
                } pthread_mutex_unlock(&(oldctx_mt->seqnr_lock));
            } else { // we are a fork
                startseqnr=oldctx_mt->seqnr;
            }
            debug_f("old seqnr = %u",startseqnr);
        }

        //Don't do this! It's not our job!
        //chachapoly_free_mt(oldctx);
    }

    struct chachapoly_ctx_mt * ctx_mt = initialize_ctx_mt(key,key+CHACHA_KEYLEN,startseqnr);
    explicit_bzero(&startseqnr,sizeof(startseqnr));

    if(ctx_mt == NULL) {
        chachapoly_free(ctx);
        debug_f("<return NULL (bad)>");
        return NULL;
    }
    EVP_CIPHER_CTX_set_app_data(ctx->main_evp, ctx_mt);
    debug3_f("<return good>");
	return ctx;
}

void
chachapoly_free_mt(struct chachapoly_ctx *cpctx)
{
    debug3_f("<debug>");
	if (cpctx == NULL)
		return;
    struct chachapoly_ctx_mt * ctx_mt = get_ctx_mt(cpctx);
    free_ctx_mt(ctx_mt); // Safe even if ctx_mt == NULL
    //This is probably unnecessary, but should be harmless.
    EVP_CIPHER_CTX_set_app_data(cpctx->main_evp,NULL);
    chachapoly_free(cpctx);
    debug3_f("<return>");
}

/*
 * chachapoly_crypt_mt() operates as following: [from serial implementation]
 * En/decrypt with header key 'aadlen' bytes from 'src', storing result
 * to 'dest'. The ciphertext here is treated as additional authenticated
 * data for MAC calculation.
 * En/decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'. Use
 * POLY1305_TAGLEN bytes at offset 'len'+'aadlen' as the authentication
 * tag. This tag is written on encryption and verified on decryption.
 *
 * NEW TO MT IMPLEMENTATION: If called without an MT context, this creates one,
 * which is slow. If creation fails, it falls back to using the serial
 * implementation of the crypt() function.
 *
 * If we're a fork, we clean up the original MT context and initialize a new
 * one.
 */
int
chachapoly_crypt_mt(struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
    debug3_f("<debug> seqnr == %u%c",seqnr,do_encrypt ? 'e' : 'd');
    struct chachapoly_ctx_mt * ctx_mt = get_ctx_mt(ctx);
    // We might have been initialized using the serial implementation, so check
    // for the MT context, and if it's not there, create it.
    if(ctx_mt == NULL) {
        ctx_mt = add_mt_to_ctx(ctx,seqnr);
        if(ctx_mt == NULL) {
            debug_f("COULD NOT CREATE CTX_MT!!!!");
            return chachapoly_crypt(ctx,seqnr,dest,src,len,aadlen,authlen,do_encrypt);
        }
    } else if(ctx_mt->mainpid != getpid()) { // we're a fork
        // The worker threads don't exist, so regenerate ctx_mt
        free_ctx_mt(ctx_mt);
        EVP_CIPHER_CTX_set_app_data(ctx->main_evp,NULL);
        ctx_mt = add_mt_to_ctx(ctx,seqnr);
    }

    // This will be the sequence number read from the pregenerated keystreams.
    // Hopefully it will match the one we want.
    u_int found_seqnr;

    // Convenience pointer to the slot where the desired keystream SHOULD be.
    struct mt_keystream * ks = &(ctx_mt->streams[seqnr % NUMSTREAMS]);
    // Return value, to reproduce the serial implementation behavior.
    int r = SSH_ERR_INTERNAL_ERROR;
    // Block if a worker is currently generating the data.
    // If trylock() is nonzero, then a worker is currently busy with the data,
    // so increment the strikes and then block. If trylock() is zero, then the
    // lock has been obtained, so proceed.
    if(pthread_mutex_trylock(&(ks->lock))) {
        ctx_mt->strikes++;
        debug_f("Caught up to workers! Strike %u! Waiting.",ctx_mt->strikes);
        pthread_mutex_lock(&(ks->lock));
    } {
        // Get the sequence number corresponding to the generated keystream
        found_seqnr = ks->seqnr;
    // No need to hold the lock, since a worker won't START working on it unless
    // the main thread doesn't need it anyway.
    } pthread_mutex_unlock(&(ks->lock));

    if(found_seqnr == seqnr) { // Good, it's the correct keystream.
        explicit_bzero(&found_seqnr,sizeof(found_seqnr));
        //check tag before anything else
        if(!do_encrypt) {
            const u_char *tag = src + aadlen + len;
            u_char expected_tag[POLY1305_TAGLEN];
            poly1305_auth(expected_tag, src, aadlen + len, ks->poly_key);
            if(timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
                r = SSH_ERR_MAC_INVALID;
            }
            explicit_bzero(expected_tag,sizeof(expected_tag));
        }
        if(r!=SSH_ERR_MAC_INVALID) {
            //Crypt additional data (specifically, the packet length)
            if(aadlen) {
                for(u_int i=0; i<aadlen; i++) {
                    dest[i]=ks->headerStream[i] ^ src[i];
                }
            }
            //Crypt payload
            for(u_int i=0; i<len; i++) {
                dest[aadlen+i]=ks->mainStream[i] ^ src[aadlen+i];
            }
            //calculate and append tag
            if(do_encrypt) {
                poly1305_auth(dest+aadlen+len,dest,aadlen+len,ks->poly_key);
            }
            r=0; // Success!
        }
        if(r) {// Anything nonzero is bad.
            debug_f("<return %d (bad)>",r);
            return r;
        }
        // Prevent a worker thread from reading seqnr while we're incrementing
        pthread_mutex_lock(&(ctx_mt->seqnr_lock)); {
            // Tell worker threads that we won't need any keystreams older than
            // seqnr + 1, whatever that is.
            ctx_mt->seqnr = seqnr+1;
        } pthread_mutex_unlock(&(ctx_mt->seqnr_lock));
        // Signal worker threads to rescan the keystreams for fresh work
        pthread_cond_broadcast(&(ctx_mt->cond));
        debug3_f("<return good>");
        return 0;
    } else { // Bad, it's the wrong keystream.
        // The keystream is either too old or completely wrong. Either way, we
        // update the sequence number in the context and signal the workers to
        // build fresh keystreams.
        ctx_mt->strikes++;
        debug_f("Cache miss! Seeking %u, found %u. Strike %u! Falling back to serial mode.",seqnr,found_seqnr,ctx_mt->strikes);
        explicit_bzero(&found_seqnr,sizeof(found_seqnr));
        // Same logic as above
        pthread_mutex_lock(&(ctx_mt->seqnr_lock)); {
            ctx_mt->seqnr = seqnr+1;
        } pthread_mutex_unlock(&(ctx_mt->seqnr_lock));
        pthread_cond_broadcast(&(ctx_mt->cond));

        // Fall back to the serial implementation.
        return chachapoly_crypt(ctx,seqnr,dest,src,len,aadlen,authlen,do_encrypt);
    }
}

/* Decrypt and extract the encrypted packet length */
/* Based on the implementation from cipher-chachapoly-libcrypto.c */
int
chachapoly_get_length_mt(struct chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
{
    debug3_f("<debug>");

    struct chachapoly_ctx_mt * ctx_mt = get_ctx_mt(ctx);
    if(ctx_mt == NULL) { // Don't bother upgrading to MT just for this.
        debug_f("No MT context. Falling back to serial mode.");
        return chachapoly_get_length(ctx,plenp,seqnr,cp,len);
    }

    if(ctx_mt->mainpid != getpid()) { // If we're a fork, fall back to serial.
        debug_f("We're a fork. Falling back to serial mode.");
        return chachapoly_get_length(ctx,plenp,seqnr,cp,len);
    }

    if (len < 4)
        return SSH_ERR_MESSAGE_INCOMPLETE;

    u_char buf[4];
    u_int found_seqnr;
    struct mt_keystream * ks = &(ctx_mt->streams[seqnr % NUMSTREAMS]);
    if(pthread_mutex_trylock(&(ks->lock))) {
        ctx_mt->strikes++;
        debug_f("Caught up to workers! Strike %u! Waiting.",ctx_mt->strikes);
        pthread_mutex_lock(&(ks->lock));
    } {
        found_seqnr = ks->seqnr;
    } pthread_mutex_unlock(&(ks->lock));

    if(found_seqnr == seqnr) {
        explicit_bzero(&found_seqnr,sizeof(found_seqnr));
        for(u_int i=0; i<sizeof(buf); i++)
            buf[i]=ks->headerStream[i] ^ cp[i];
        *plenp = PEEK_U32(buf);
        return 0;
    } else {
        ctx_mt->strikes++;
        debug_f("Cache miss! Seeking %u, found %u. Strike %u! Falling back to serial mode.",seqnr,found_seqnr,ctx_mt->strikes);
        explicit_bzero(&found_seqnr,sizeof(found_seqnr));
        return chachapoly_get_length(ctx,plenp,seqnr,cp,len);
    }
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
