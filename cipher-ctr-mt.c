/*
 * OpenSSH Multi-threaded AES-CTR Cipher
 *
 * Author: Benjamin Bennett <ben@psc.edu>
 * Author: Mike Tasota <tasota@gmail.com>
 * Author: Chris Rapier <rapier@psc.edu>
 * Copyright (c) 2008-2013 Pittsburgh Supercomputing Center. All rights reserved.
 *
 * Based on original OpenSSH AES-CTR cipher. Small portions remain unchanged,
 * Copyright (c) 2003 Markus Friedl <markus@openbsd.org>
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

#if defined(WITH_OPENSSL)
#include <sys/types.h>

#include <stdarg.h>
#include <string.h>

#include <openssl/evp.h>

#include "xmalloc.h"
#include "log.h"
#include <unistd.h>

/* compatibility with old or broken OpenSSL versions */
#include "openbsd-compat/openssl-compat.h"

#ifndef USE_BUILTIN_RIJNDAEL
#include <openssl/aes.h>
#endif

#include <pthread.h>

/*-------------------- TUNABLES --------------------*/
/* maximum number of threads and queues */
#define MAX_THREADS      32 
#define MAX_NUMKQ        (MAX_THREADS * 2)

/* Number of pregen threads to use */
int cipher_threads = 2;

/* Number of keystream queues */
int numkq = 4;

/* Length of a keystream queue */
#define KQLEN		4096

/* Processor cacheline length */
#define CACHELINE_LEN	64

/* Collect thread stats and print at cancellation when in debug mode */
#define CIPHER_THREAD_STATS

/* Can the system do unaligned loads natively? */
#if defined(__aarch64__) || \
    defined(__i386__)    || \
    defined(__powerpc__) || \
    defined(__x86_64__)
# define CIPHER_UNALIGNED_OK
#endif
#if defined(__SIZEOF_INT128__)
# define CIPHER_INT128_OK
#endif
/*-------------------- END TUNABLES --------------------*/


const EVP_CIPHER *evp_aes_ctr_mt(void);

#ifdef CIPHER_THREAD_STATS
/*
 * Struct to collect thread stats
 */
struct thread_stats {
	u_int	fills;
	u_int	skips;
	u_int	waits;
	u_int	drains;
};

/*
 * Debug print the thread stats
 * Use with pthread_cleanup_push for displaying at thread cancellation
 */
static void
thread_loop_stats(void *x)
{
	struct thread_stats *s = x;

	debug("AES-CTR MT tid %lu - %u fills, %u skips, %u waits", pthread_self(),
			s->fills, s->skips, s->waits);
}

# define STATS_STRUCT(s)	struct thread_stats s
# define STATS_INIT(s)		{ memset(&s, 0, sizeof(s)); }
# define STATS_FILL(s)		{ s.fills++; }
# define STATS_SKIP(s)		{ s.skips++; }
# define STATS_WAIT(s)		{ s.waits++; }
# define STATS_DRAIN(s)		{ s.drains++; }
#else
# define STATS_STRUCT(s)
# define STATS_INIT(s)
# define STATS_FILL(s)
# define STATS_SKIP(s)
# define STATS_WAIT(s)
# define STATS_DRAIN(s)
#endif

/* Keystream Queue state */
enum {
	KQINIT,
	KQEMPTY,
	KQFILLING,
	KQFULL,
	KQDRAINING
};

/* Keystream Queue struct */
struct kq {
	u_char		keys[KQLEN][AES_BLOCK_SIZE];
	u_char		ctr[AES_BLOCK_SIZE];
	u_char		pad0[CACHELINE_LEN];
	int		qstate;
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	u_char		pad1[CACHELINE_LEN];
};

/* Context struct */
struct ssh_aes_ctr_ctx_mt
{
	int             struct_id;
	struct kq	q[MAX_NUMKQ];
	AES_KEY		aes_ctx;
	STATS_STRUCT(stats);
	u_char		aes_counter[AES_BLOCK_SIZE];
	pthread_t	tid[MAX_THREADS];
	int             id[MAX_THREADS];
	pthread_rwlock_t tid_lock;
#ifdef __APPLE__
	pthread_rwlock_t stop_lock;
	int		exit_flag;
#endif /* __APPLE__ */
	int		state;
	int		qidx;
	int		ridx;
};

/* <friedl>
 * increment counter 'ctr',
 * the counter is of size 'len' bytes and stored in network-byte-order.
 * (LSB at ctr[len-1], MSB at ctr[0])
 */
static void
ssh_ctr_inc(u_char *ctr, size_t len)
{
	int i;

	for (i = len - 1; i >= 0; i--)
		if (++ctr[i])	/* continue on overflow */
			return;
}

/*
 * Add num to counter 'ctr'
 */
static void
ssh_ctr_add(u_char *ctr, uint32_t num, u_int len)
{
	int i;
	uint16_t n;

	for (n = 0, i = len - 1; i >= 0 && (num || n); i--) {
		n = ctr[i] + (num & 0xff) + n;
		num >>= 8;
		ctr[i] = n & 0xff;
		n >>= 8;
	}
}

/*
 * Threads may be cancelled in a pthread_cond_wait, we must free the mutex
 */
static void
thread_loop_cleanup(void *x)
{
	pthread_mutex_unlock((pthread_mutex_t *)x);
}

#ifdef __APPLE__
/* Check if we should exit, we are doing both cancel and exit condition
 * since on OSX threads seem to occasionally fail to notice when they have
 * been cancelled. We want to have a backup to make sure that we won't hang
 * when the main process join()-s the cancelled thread.
 */
static void
thread_loop_check_exit(struct ssh_aes_ctr_ctx_mt *c)
{
	int exit_flag;

	pthread_rwlock_rdlock(&c->stop_lock);
	exit_flag = c->exit_flag;
	pthread_rwlock_unlock(&c->stop_lock);

	if (exit_flag)
		pthread_exit(NULL);
}
#else
# define thread_loop_check_exit(s)
#endif /* __APPLE__ */

/*
 * Helper function to terminate the helper threads
 */
static void
stop_and_join_pregen_threads(struct ssh_aes_ctr_ctx_mt *c)
{
	int i;

#ifdef __APPLE__
	/* notify threads that they should exit */
	pthread_rwlock_wrlock(&c->stop_lock);
	c->exit_flag = TRUE;
	pthread_rwlock_unlock(&c->stop_lock);
#endif /* __APPLE__ */

	/* Cancel pregen threads */
	for (i = 0; i < cipher_threads; i++) {
		debug ("Canceled %lu (%d,%d)", c->tid[i], c->struct_id, c->id[i]);
		pthread_cancel(c->tid[i]);
	}
	/* shouldn't need this - see commit logs for hpn-7_7_P1 -cjr 11/7/19*/
	/* for (i = 0; i < numkq; i++) { */
	/* 	pthread_mutex_lock(&c->q[i].lock); */
	/* 	pthread_cond_broadcast(&c->q[i].cond); */
	/* 	pthread_mutex_unlock(&c->q[i].lock); */
	/* } */
	for (i = 0; i < cipher_threads; i++) {
		if (pthread_kill(c->tid[i], 0) != 0)
			debug3("AES-CTR MT pthread_join failure: Invalid thread id %lu in %s", c->tid[i], __FUNCTION__);
		else {
			debug ("Joining %lu (%d, %d)", c->tid[i], c->struct_id, c->id[i]);
			pthread_join(c->tid[i], NULL);
		}
	}
}

/*
 * The life of a pregen thread:
 *    Find empty keystream queues and fill them using their counter.
 *    When done, update counter for the next fill.
 */
static void *
thread_loop(void *x)
{
	AES_KEY key;
	STATS_STRUCT(stats);
	struct ssh_aes_ctr_ctx_mt *c = x;
	struct kq *q;
	int i;
	int qidx;
	pthread_t first_tid;

	/* Threads stats on cancellation */
	STATS_INIT(stats);
#ifdef CIPHER_THREAD_STATS
	pthread_cleanup_push(thread_loop_stats, &stats);
#endif

	/* Thread local copy of AES key */
	memcpy(&key, &c->aes_ctx, sizeof(key));

	pthread_rwlock_rdlock(&c->tid_lock);
	first_tid = c->tid[0];
	pthread_rwlock_unlock(&c->tid_lock);

	/*
	 * Handle the special case of startup, one thread must fill
	 * the first KQ then mark it as draining. Lock held throughout.
	 */
	if (pthread_equal(pthread_self(), first_tid)) {
		q = &c->q[0];
		pthread_mutex_lock(&q->lock);
		if (q->qstate == KQINIT) {
			for (i = 0; i < KQLEN; i++) {
				AES_encrypt(q->ctr, q->keys[i], &key);
				ssh_ctr_inc(q->ctr, AES_BLOCK_SIZE);
			}
			ssh_ctr_add(q->ctr, KQLEN * (numkq - 1), AES_BLOCK_SIZE);
			q->qstate = KQDRAINING;
			STATS_FILL(stats);
			pthread_cond_broadcast(&q->cond);
		}
		pthread_mutex_unlock(&q->lock);
	} else
		STATS_SKIP(stats);

	/*
	 * Normal case is to find empty queues and fill them, skipping over
	 * queues already filled by other threads and stopping to wait for
	 * a draining queue to become empty.
	 *
	 * Multiple threads may be waiting on a draining queue and awoken
	 * when empty.  The first thread to wake will mark it as filling,
	 * others will move on to fill, skip, or wait on the next queue.
	 */
	for (qidx = 1;; qidx = (qidx + 1) % numkq) {
		/* Check if I was cancelled, also checked in cond_wait */
		pthread_testcancel();

		/* Check if we should exit as well */
		thread_loop_check_exit(c);

		/* Lock queue and block if its draining */
		q = &c->q[qidx];
		pthread_mutex_lock(&q->lock);
		pthread_cleanup_push(thread_loop_cleanup, &q->lock);
		while (q->qstate == KQDRAINING || q->qstate == KQINIT) {
			STATS_WAIT(stats);
			thread_loop_check_exit(c);
			pthread_cond_wait(&q->cond, &q->lock);
		}
		pthread_cleanup_pop(0);

		/* If filling or full, somebody else got it, skip */
		if (q->qstate != KQEMPTY) {
			pthread_mutex_unlock(&q->lock);
			STATS_SKIP(stats);
			continue;
		}

		/*
		 * Empty, let's fill it.
		 * Queue lock is relinquished while we do this so others
		 * can see that it's being filled.
		 */
		q->qstate = KQFILLING;
		pthread_cond_broadcast(&q->cond);
		pthread_mutex_unlock(&q->lock);
		for (i = 0; i < KQLEN; i++) {
			AES_encrypt(q->ctr, q->keys[i], &key);
			ssh_ctr_inc(q->ctr, AES_BLOCK_SIZE);
		}

		/* Re-lock, mark full and signal consumer */
		pthread_mutex_lock(&q->lock);
		ssh_ctr_add(q->ctr, KQLEN * (numkq - 1), AES_BLOCK_SIZE);
		q->qstate = KQFULL;
		STATS_FILL(stats);
		pthread_cond_broadcast(&q->cond);
		pthread_mutex_unlock(&q->lock);
	}

#ifdef CIPHER_THREAD_STATS
	/* Stats */
	pthread_cleanup_pop(1);
#endif

	return NULL;
}

static int
ssh_aes_ctr(EVP_CIPHER_CTX *ctx, u_char *dest, const u_char *src,
    LIBCRYPTO_EVP_INL_TYPE len)
{
	typedef union {
#ifdef CIPHER_INT128_OK
		__uint128_t *u128;
#endif
		uint64_t *u64;
		uint32_t *u32;
		uint8_t *u8;
		const uint8_t *cu8;
		uintptr_t u;
	} ptrs_t;
	ptrs_t destp, srcp, bufp;
	uintptr_t align;
	struct ssh_aes_ctr_ctx_mt *c;
	struct kq *q, *oldq;
	int ridx;
	u_char *buf;

	if (len == 0)
		return 1;
	if ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == NULL)
		return 0;

	q = &c->q[c->qidx];
	ridx = c->ridx;

	/* src already padded to block multiple */
	srcp.cu8 = src;
	destp.u8 = dest;
	while (len > 0) {
		buf = q->keys[ridx];
		bufp.u8 = buf;

		/* figure out the alignment on the fly */
#ifdef CIPHER_UNALIGNED_OK
		align = 0;
#else
		align = destp.u | srcp.u | bufp.u;
#endif

#ifdef CIPHER_INT128_OK
		if ((align & 0xf) == 0) {
			destp.u128[0] = srcp.u128[0] ^ bufp.u128[0];
		} else
#endif
		if ((align & 0x7) == 0) {
			destp.u64[0] = srcp.u64[0] ^ bufp.u64[0];
			destp.u64[1] = srcp.u64[1] ^ bufp.u64[1];
		} else if ((align & 0x3) == 0) {
			destp.u32[0] = srcp.u32[0] ^ bufp.u32[0];
			destp.u32[1] = srcp.u32[1] ^ bufp.u32[1];
			destp.u32[2] = srcp.u32[2] ^ bufp.u32[2];
			destp.u32[3] = srcp.u32[3] ^ bufp.u32[3];
		} else {
			size_t i;
			for (i = 0; i < AES_BLOCK_SIZE; ++i)
				dest[i] = src[i] ^ buf[i];
		}

		destp.u += AES_BLOCK_SIZE;
		srcp.u += AES_BLOCK_SIZE;
		len -= AES_BLOCK_SIZE;
		ssh_ctr_inc(c->aes_counter, AES_BLOCK_SIZE);

		/* Increment read index, switch queues on rollover */
		if ((ridx = (ridx + 1) % KQLEN) == 0) {
			oldq = q;

			/* Mark next queue draining, may need to wait */
			c->qidx = (c->qidx + 1) % numkq;
			q = &c->q[c->qidx];
			pthread_mutex_lock(&q->lock);
			while (q->qstate != KQFULL) {
				STATS_WAIT(c->stats);
				pthread_cond_wait(&q->cond, &q->lock);
			}
			q->qstate = KQDRAINING;
			pthread_cond_broadcast(&q->cond);
			pthread_mutex_unlock(&q->lock);

			/* Mark consumed queue empty and signal producers */
			pthread_mutex_lock(&oldq->lock);
			oldq->qstate = KQEMPTY;
			STATS_DRAIN(c->stats);
			pthread_cond_broadcast(&oldq->cond);
			pthread_mutex_unlock(&oldq->lock);
		}
	}
	c->ridx = ridx;
	return 1;
}

#define HAVE_NONE       0
#define HAVE_KEY        1
#define HAVE_IV         2

int X = 0;

static int
ssh_aes_ctr_init(EVP_CIPHER_CTX *ctx, const u_char *key, const u_char *iv,
    int enc)
{
	struct ssh_aes_ctr_ctx_mt *c;
	int i;

	/* get the number of cores in the system */
	/* if it's not linux it currently defaults to 2 */
	/* divide by 2 to get threads for each direction (MODE_IN||MODE_OUT) */
#ifdef __linux__
	cipher_threads = sysconf(_SC_NPROCESSORS_ONLN) / 2;
#endif /*__linux__*/
#ifdef __APPLE__
	cipher_threads = sysconf(_SC_NPROCESSORS_ONLN) / 2;
#endif /*__APPLE__*/
#ifdef __FREEBSD__
	int req[2];
	size_t len;

	req[0] = CTL_HW;
	req[1] = HW_NCPU;

	len = sizeof(ncpu);
        sysctl(req, 2, &cipher_threads, &len, NULL, 0);
	cipher_threads = cipher_threads / 2;
#endif /*__FREEBSD__*/

	/* if they have less than 4 cores spin up 4 threads anyway */
	if (cipher_threads < 2) 
		cipher_threads = 2;
		
	/* assure that we aren't trying to create more threads */
	/* than we have in the struct. cipher_threads is half the */
	/* total of allowable threads hence the odd looking math here */
	if (cipher_threads * 2 > MAX_THREADS)
		cipher_threads = MAX_THREADS / 2;

	/* set the number of keystream queues */
	numkq = cipher_threads * 2;

	if ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == NULL) {
		c = xmalloc(sizeof(*c));
		pthread_rwlock_init(&c->tid_lock, NULL);
#ifdef __APPLE__
		pthread_rwlock_init(&c->stop_lock, NULL);
		c->exit_flag = FALSE;
#endif /* __APPLE__ */

		c->state = HAVE_NONE;
		for (i = 0; i < numkq; i++) {
			pthread_mutex_init(&c->q[i].lock, NULL);
			pthread_cond_init(&c->q[i].cond, NULL);
		}

		STATS_INIT(c->stats);
		EVP_CIPHER_CTX_set_app_data(ctx, c);
	}

	if (c->state == (HAVE_KEY | HAVE_IV)) {
		/* tell the pregen threads to exit */
		stop_and_join_pregen_threads(c);
		
#ifdef __APPLE__
		/* reset the exit flag */
		c->exit_flag = FALSE;
#endif /* __APPLE__ */

		/* Start over getting key & iv */
		c->state = HAVE_NONE;
	}

	if (key != NULL) {
		AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
		    &c->aes_ctx);
		c->state |= HAVE_KEY;
	}

	if (iv != NULL) {
		memcpy(c->aes_counter, iv, AES_BLOCK_SIZE);
		c->state |= HAVE_IV;
	}

	if (c->state == (HAVE_KEY | HAVE_IV)) {
		/* Clear queues */
		memcpy(c->q[0].ctr, c->aes_counter, AES_BLOCK_SIZE);
		c->q[0].qstate = KQINIT;
		for (i = 1; i < numkq; i++) {
			memcpy(c->q[i].ctr, c->aes_counter, AES_BLOCK_SIZE);
			ssh_ctr_add(c->q[i].ctr, i * KQLEN, AES_BLOCK_SIZE);
			c->q[i].qstate = KQEMPTY;
		}
		c->qidx = 0;
		c->ridx = 0;

		/* Start threads */
		for (i = 0; i < cipher_threads; i++) {
			pthread_rwlock_wrlock(&c->tid_lock);
			if (pthread_create(&c->tid[i], NULL, thread_loop, c) != 0)
				debug ("AES-CTR MT Could not create thread in %s", __FUNCTION__); /*should die here */
			else {
				if (!c->struct_id)
					c->struct_id = X++;
				c->id[i] = i;
				debug ("AES-CTR MT spawned a thread with id %lu in %s (%d, %d)", c->tid[i], __FUNCTION__, c->struct_id, c->id[i]);
			}
			pthread_rwlock_unlock(&c->tid_lock);
		}
		pthread_mutex_lock(&c->q[0].lock);
		while (c->q[0].qstate == KQINIT)
			pthread_cond_wait(&c->q[0].cond, &c->q[0].lock);
		pthread_mutex_unlock(&c->q[0].lock);
	}
	return 1;
}

/* this function is no longer used but might prove handy in the future
 * this comment also applies to ssh_aes_ctr_thread_reconstruction
 */
void
ssh_aes_ctr_thread_destroy(EVP_CIPHER_CTX *ctx)
{
	struct ssh_aes_ctr_ctx_mt *c;

	c = EVP_CIPHER_CTX_get_app_data(ctx);
	stop_and_join_pregen_threads(c);
}

void
ssh_aes_ctr_thread_reconstruction(EVP_CIPHER_CTX *ctx)
{
	struct ssh_aes_ctr_ctx_mt *c;
	int i;
	c = EVP_CIPHER_CTX_get_app_data(ctx);
	/* reconstruct threads */
	for (i = 0; i < cipher_threads; i++) {
		pthread_rwlock_wrlock(&c->tid_lock);
		if (pthread_create(&c->tid[i], NULL, thread_loop, c) !=0 )
			debug("AES-CTR MT could not create thread in %s", __FUNCTION__);
		else {
			c->struct_id = X++;
			c->id[i] = i;
			debug ("AES-CTR MT spawned a thread with id %lu in %s (%d, %d)", c->tid[i], __FUNCTION__, c->struct_id, c->id[i]);
			debug("AES-CTR MT spawned a thread with id %lu in %s", c->tid[i], __FUNCTION__);
		}
		pthread_rwlock_unlock(&c->tid_lock);
	}
}

static int
ssh_aes_ctr_cleanup(EVP_CIPHER_CTX *ctx)
{
	struct ssh_aes_ctr_ctx_mt *c;

	if ((c = EVP_CIPHER_CTX_get_app_data(ctx)) != NULL) {
#ifdef CIPHER_THREAD_STATS
		debug("AES-CTR MT main thread: %u drains, %u waits", c->stats.drains,
		      c->stats.waits);
#endif
		stop_and_join_pregen_threads(c);

		memset(c, 0, sizeof(*c));
		free(c);
		EVP_CIPHER_CTX_set_app_data(ctx, NULL);
	}
	return 1;
}

/* <friedl> */
const EVP_CIPHER *
evp_aes_ctr_mt(void)
{
# if OPENSSL_VERSION_NUMBER >= 0x10100000UL
	static EVP_CIPHER *aes_ctr;
	aes_ctr = EVP_CIPHER_meth_new(NID_undef, 16/*block*/, 16/*key*/);
	EVP_CIPHER_meth_set_iv_length(aes_ctr, AES_BLOCK_SIZE);
	EVP_CIPHER_meth_set_init(aes_ctr, ssh_aes_ctr_init);
	EVP_CIPHER_meth_set_cleanup(aes_ctr, ssh_aes_ctr_cleanup);
	EVP_CIPHER_meth_set_do_cipher(aes_ctr, ssh_aes_ctr);
#  ifndef SSH_OLD_EVP
	EVP_CIPHER_meth_set_flags(aes_ctr, EVP_CIPH_CBC_MODE
				      | EVP_CIPH_VARIABLE_LENGTH
				      | EVP_CIPH_ALWAYS_CALL_INIT
				      | EVP_CIPH_CUSTOM_IV);
#  endif /*SSH_OLD_EVP*/
	return (aes_ctr);
# else /*earlier versions of openssl*/
	static EVP_CIPHER aes_ctr;
	memset(&aes_ctr, 0, sizeof(EVP_CIPHER));
	aes_ctr.nid = NID_undef;
	aes_ctr.block_size = AES_BLOCK_SIZE;
	aes_ctr.iv_len = AES_BLOCK_SIZE;
	aes_ctr.key_len = 16;
	aes_ctr.init = ssh_aes_ctr_init;
	aes_ctr.cleanup = ssh_aes_ctr_cleanup;
	aes_ctr.do_cipher = ssh_aes_ctr;
#  ifndef SSH_OLD_EVP
        aes_ctr.flags = EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH |
		EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#  endif /*SSH_OLD_EVP*/
        return &aes_ctr;
# endif /*OPENSSH_VERSION_NUMBER*/
}

#endif /* defined(WITH_OPENSSL) */
