/*
 * OpenSSH Multi-threaded AES-CTR Cipher Provider for OpenSSL 3
 *
 * Author: Benjamin Bennett <ben@psc.edu>
 * Author: Mike Tasota <tasota@gmail.com>
 * Author: Chris Rapier <rapier@psc.edu>
 * Copyright (c) 2008-2022 Pittsburgh Supercomputing Center. All rights reserved.
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

#ifndef CTR_MT_FUNCS
#define CTR_MT_FUNCS

/* includes */
#include "includes.h" /* needed to get version number */
#include <sys/types.h>
#include <pthread.h>
#include "cipher-aesctr.h"

#ifndef USE_BUILTIN_RIJNDAEL
#include <openssl/aes.h>
#endif

#ifdef WITH_OPENSSL
/* only for systems with OSSL 3 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000UL

/*-------------------- TUNABLES --------------------*/
/* maximum number of threads and queues */
#define MAX_THREADS      32
#define MAX_NUMKQ        (MAX_THREADS + 1)

/* one queue holds 8192 * 4 * 16B (512KB)  of key data 
 * being that the queues are destroyed after a rekey
 * and at leats one has to be fully filled prior to
 * enciphering data we don't want this to be too large */
#define KQLEN (8192 * 4)

/* Processor cacheline length */
#define CACHELINE_LEN	64

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

/* context states */
#define HAVE_NONE       0
#define HAVE_KEY        1
#define HAVE_IV         2

/* Keystream Queue state */
enum {
	KQINIT,
	KQEMPTY,
	KQFILLING,
	KQFULL,
	KQDRAINING
};

/* structs */

/* provider struct */
struct provider_ctx_st {
	const OSSL_CORE_HANDLE *core_handle;
	struct proverr_functions_st *proverr_handle;
};

/* Keystream Queue struct */
struct kq {
	u_char		keys[KQLEN][AES_BLOCK_SIZE]; /* [32768][16B] */
	u_char		ctr[AES_BLOCK_SIZE]; /* 16B */
	u_char          pad0[CACHELINE_LEN];
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	int             qstate;
	u_char          pad1[CACHELINE_LEN];
};

/* AES MT context struct */
struct aes_mt_ctx_st {
	struct provider_ctx_st *provctx;
	int             struct_id;
	int             keylen;
	int		state;
	int		qidx;
	int		ridx;
	int             id[MAX_THREADS]; /* 32 */
	AES_KEY         aes_key;
	const u_char    *orig_key;
	u_char		aes_counter[AES_BLOCK_SIZE]; /* 16B */
	pthread_t	tid[MAX_THREADS]; /* 32 */
	pthread_rwlock_t tid_lock;
	struct kq	q[MAX_NUMKQ]; /* 33 */
#ifdef __APPLE__
	pthread_rwlock_t stop_lock;
	int		exit_flag;
#endif /* __APPLE__ */
	int             ongoing; /* possibly not needed */
};

int aes_mt_do_cipher(void *, u_char *, size_t *, size_t, const u_char *, size_t);
int aes_mt_start_threads(void *, const u_char *, size_t, const u_char *, size_t, const OSSL_PARAM *);
void aes_mt_freectx(void *);
void *aes_mt_newctx_256(void *);
void *aes_mt_newctx_192(void *);
void *aes_mt_newctx_128(void *);

#endif /* VERSION NUMBER */
#endif /* WITH OPENSSL */
#endif /* CTR_MT_FUNCS */
