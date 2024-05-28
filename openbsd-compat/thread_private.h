/* $OpenBSD: thread_private.h,v 1.36 2021/01/06 19:54:17 otto Exp $ */

/* PUBLIC DOMAIN: No Rights Reserved. Marco S Hyman <marc@snafu.org> */

#ifndef _THREAD_PRIVATE_H_
#define _THREAD_PRIVATE_H_

#include <stdio.h>		/* for FILE and __isthreaded */

#define _MALLOC_MUTEXES 32
void _malloc_init(int);
#ifdef __LIBC__
PROTO_NORMAL(_malloc_init);
#endif /* __LIBC__ */

/*
 * The callbacks needed by libc to handle the threaded case.
 * NOTE: Bump the version when you change the struct contents!
 *
 * tc_canceled:
 *	If not NULL, what to do when canceled (otherwise _exit(0))
 *
 * tc_flockfile, tc_ftrylockfile, and tc_funlockfile:
 *	If not NULL, these implement the flockfile() family.
 *	XXX In theory, you should be able to lock a FILE before
 *	XXX loading libpthread and have that be a real lock on it,
 *	XXX but that doesn't work without the libc base version
 *	XXX tracking the recursion count.
 *
 * tc_malloc_lock and tc_malloc_unlock:
 * tc_atexit_lock and tc_atexit_unlock:
 * tc_atfork_lock and tc_atfork_unlock:
 * tc_arc4_lock and tc_arc4_unlock:
 *	The locks used by the malloc, atexit, atfork, and arc4 subsystems.
 *	These have to be ordered specially in the fork/vfork wrappers
 *	and may be implemented differently than the general mutexes
 *	in the callbacks below.
 *
 * tc_mutex_lock and tc_mutex_unlock:
 *	Lock and unlock the given mutex. If the given mutex is NULL
 *	a mutex is allocated and initialized automatically.
 *
 * tc_mutex_destroy:
 *	Destroy/deallocate the given mutex.
 *
 * tc_tag_lock and tc_tag_unlock:
 *	Lock and unlock the mutex associated with the given tag.
 *	If the given tag is NULL a tag is allocated and initialized
 *	automatically.
 *
 * tc_tag_storage:
 *	Returns a pointer to per-thread instance of data associated
 *	with the given tag.  If the given tag is NULL a tag is
 *	allocated and initialized automatically.
 *
 * tc_fork, tc_vfork:
 *	If not NULL, they are called instead of the syscall stub, so that
 *	the thread library can do necessary locking and reinitialization.
 *
 * tc_thread_release:
 *	Handles the release of a thread's TIB and struct pthread and the
 *	notification of other threads...when there are other threads.
 *
 * tc_thread_key_zero:
 *	For each thread, zero out the key data associated with the given key.

 * If <machine/tcb.h> doesn't define TCB_GET(), then locating the TCB in a
 * threaded process requires a syscall (__get_tcb(2)) which is too much
 * overhead for single-threaded processes.  For those archs, there are two
 * additional callbacks, though they are placed first in the struct for
 * convenience in ASM:
 *
 * tc_errnoptr:
 *	Returns the address of the thread's errno.
 *
 * tc_tcb:
 *	Returns the address of the thread's TCB.
 */

struct pthread;
struct thread_callbacks {
	int	*(*tc_errnoptr)(void);		/* MUST BE FIRST */
	void	*(*tc_tcb)(void);
	void	(*tc_canceled)(void);
	void	(*tc_flockfile)(FILE *);
	int	(*tc_ftrylockfile)(FILE *);
	void	(*tc_funlockfile)(FILE *);
	void	(*tc_malloc_lock)(int);
	void	(*tc_malloc_unlock)(int);
	void	(*tc_atexit_lock)(void);
	void	(*tc_atexit_unlock)(void);
	void	(*tc_atfork_lock)(void);
	void	(*tc_atfork_unlock)(void);
	void	(*tc_arc4_lock)(void);
	void	(*tc_arc4_unlock)(void);
	void	(*tc_mutex_lock)(void **);
	void	(*tc_mutex_unlock)(void **);
	void	(*tc_mutex_destroy)(void **);
	void	(*tc_tag_lock)(void **);
	void	(*tc_tag_unlock)(void **);
	void	*(*tc_tag_storage)(void **, void *, size_t, void (*)(void *),
	   void *);
	__pid_t	(*tc_fork)(void);
	__pid_t	(*tc_vfork)(void);
	void	(*tc_thread_release)(struct pthread *);
	void	(*tc_thread_key_zero)(int);
};

/*
 *  Set the callbacks used by libc
 */
void	_thread_set_callbacks(const struct thread_callbacks *_cb, size_t _len);

#ifdef __LIBC__
__BEGIN_HIDDEN_DECLS
/* the current set */
extern struct thread_callbacks _thread_cb;
__END_HIDDEN_DECLS
#endif /* __LIBC__ */

/*
 * helper macro to make unique names in the thread namespace
 */
#define __THREAD_NAME(name)	__CONCAT(_thread_tagname_,name)

/*
 * Macros used in libc to access thread mutex, keys, and per thread storage.
 * _THREAD_PRIVATE_KEY and _THREAD_PRIVATE_MUTEX are different macros for
 * historical reasons.   They do the same thing, define a static variable
 * keyed by 'name' that identifies a mutex and a key to identify per thread
 * data.
 */
#define _THREAD_PRIVATE_KEY(name)					\
	static void *__THREAD_NAME(name)
#define _THREAD_PRIVATE_MUTEX(name)					\
	static void *__THREAD_NAME(name)


#ifndef __LIBC__	/* building some sort of reach around */

#define _THREAD_PRIVATE_MUTEX_LOCK(name)		do {} while (0)
#define _THREAD_PRIVATE_MUTEX_UNLOCK(name)		do {} while (0)
#define _THREAD_PRIVATE(keyname, storage, error)	&(storage)
#define _THREAD_PRIVATE_DT(keyname, storage, dt, error)	&(storage)
#define _MUTEX_LOCK(mutex)				do {} while (0)
#define _MUTEX_UNLOCK(mutex)				do {} while (0)
#define _MUTEX_DESTROY(mutex)				do {} while (0)
#define _MALLOC_LOCK(n)					do {} while (0)
#define _MALLOC_UNLOCK(n)				do {} while (0)
#define _ATEXIT_LOCK()					do {} while (0)
#define _ATEXIT_UNLOCK()				do {} while (0)
#define _ATFORK_LOCK()					do {} while (0)
#define _ATFORK_UNLOCK()				do {} while (0)
#define _ARC4_LOCK()					do {} while (0)
#define _ARC4_UNLOCK()					do {} while (0)

#else		/* building libc */
#define _THREAD_PRIVATE_MUTEX_LOCK(name)				\
	do {								\
		if (_thread_cb.tc_tag_lock != NULL)			\
			_thread_cb.tc_tag_lock(&(__THREAD_NAME(name)));	\
	} while (0)
#define _THREAD_PRIVATE_MUTEX_UNLOCK(name)				\
	do {								\
		if (_thread_cb.tc_tag_unlock != NULL)			\
			_thread_cb.tc_tag_unlock(&(__THREAD_NAME(name))); \
	} while (0)
#define _THREAD_PRIVATE(keyname, storage, error)			\
	(_thread_cb.tc_tag_storage == NULL ? &(storage) :		\
	    _thread_cb.tc_tag_storage(&(__THREAD_NAME(keyname)),	\
		&(storage), sizeof(storage), NULL, (error)))

#define _THREAD_PRIVATE_DT(keyname, storage, dt, error)			\
	(_thread_cb.tc_tag_storage == NULL ? &(storage) :		\
	    _thread_cb.tc_tag_storage(&(__THREAD_NAME(keyname)),	\
		&(storage), sizeof(storage), (dt), (error)))

/*
 * Macros used in libc to access mutexes.
 */
#define _MUTEX_LOCK(mutex)						\
	do {								\
		if (__isthreaded)					\
			_thread_cb.tc_mutex_lock(mutex);		\
	} while (0)
#define _MUTEX_UNLOCK(mutex)						\
	do {								\
		if (__isthreaded)					\
			_thread_cb.tc_mutex_unlock(mutex);		\
	} while (0)
#define _MUTEX_DESTROY(mutex)						\
	do {								\
		if (__isthreaded)					\
			_thread_cb.tc_mutex_destroy(mutex);		\
	} while (0)

/*
 * malloc lock/unlock prototypes and definitions
 */
#define _MALLOC_LOCK(n)							\
	do {								\
		if (__isthreaded)					\
			_thread_cb.tc_malloc_lock(n);			\
	} while (0)
#define _MALLOC_UNLOCK(n)						\
	do {								\
		if (__isthreaded)					\
			_thread_cb.tc_malloc_unlock(n);			\
	} while (0)

#define _ATEXIT_LOCK()							\
	do {								\
		if (__isthreaded)					\
			_thread_cb.tc_atexit_lock();			\
	} while (0)
#define _ATEXIT_UNLOCK()						\
	do {								\
		if (__isthreaded)					\
			_thread_cb.tc_atexit_unlock();			\
	} while (0)

#define _ATFORK_LOCK()							\
	do {								\
		if (__isthreaded)					\
			_thread_cb.tc_atfork_lock();			\
	} while (0)
#define _ATFORK_UNLOCK()						\
	do {								\
		if (__isthreaded)					\
			_thread_cb.tc_atfork_unlock();			\
	} while (0)

#define _ARC4_LOCK()							\
	do {								\
		if (__isthreaded)					\
			_thread_cb.tc_arc4_lock();			\
	} while (0)
#define _ARC4_UNLOCK()							\
	do {								\
		if (__isthreaded)					\
			_thread_cb.tc_arc4_unlock();			\
	} while (0)
#endif /* __LIBC__ */


/*
 * Copyright (c) 2004,2005 Ted Unangst <tedu@openbsd.org>
 * All Rights Reserved.
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
/*
 * Private data structures that back up the typedefs in pthread.h.
 * Since only the thread library cares about their size or arrangement,
 * it should be possible to switch libraries without relinking.
 *
 * Do not reorder _atomic_lock_t and sem_t variables in the structs.
 * This is due to alignment requirements of certain arches like hppa.
 * The current requirement is 16 bytes.
 *
 * THE MACHINE DEPENDENT CERROR CODE HAS HARD CODED OFFSETS INTO PTHREAD_T!
 */

#include <sys/queue.h>
#include <pthread.h>
#include <semaphore.h>
#include "machine/spinlock.h"

#define	_SPINLOCK_UNLOCKED _ATOMIC_LOCK_UNLOCKED

struct __sem {
	_atomic_lock_t lock;
	volatile int waitcount;
	volatile int value;
	int shared;
};

TAILQ_HEAD(pthread_queue, pthread);

#ifdef FUTEX

struct pthread_mutex {
	volatile unsigned int lock;
	int type;
	pthread_t owner;
	int count;
	int prioceiling;
};

struct pthread_cond {
	volatile unsigned int seq;
	clockid_t clock;
	struct pthread_mutex *mutex;
};

struct pthread_rwlock {
	volatile unsigned int value;
};

#else

struct pthread_mutex {
	_atomic_lock_t lock;
	struct pthread_queue lockers;
	int type;
	pthread_t owner;
	int count;
	int prioceiling;
};

struct pthread_cond {
	_atomic_lock_t lock;
	struct pthread_queue waiters;
	struct pthread_mutex *mutex;
	clockid_t clock;
};

struct pthread_rwlock {
	_atomic_lock_t lock;
	pthread_t owner;
	struct pthread_queue writers;
	int readers;
};
#endif /* FUTEX */

struct pthread_mutex_attr {
	int ma_type;
	int ma_protocol;
	int ma_prioceiling;
};

struct pthread_cond_attr {
	clockid_t ca_clock;
};

struct pthread_attr {
	void *stack_addr;
	size_t stack_size;
	size_t guard_size;
	int detach_state;
	int contention_scope;
	int sched_policy;
	struct sched_param sched_param;
	int sched_inherit;
};

struct rthread_storage {
	int keyid;
	struct rthread_storage *next;
	void *data;
};

struct rthread_cleanup_fn {
	void (*fn)(void *);
	void *arg;
	struct rthread_cleanup_fn *next;
};

struct tib;
struct stack;
struct pthread {
	struct __sem donesem;
	unsigned int flags;
	_atomic_lock_t flags_lock;
	struct tib *tib;
	void *retval;
	void *(*fn)(void *);
	void *arg;
	char name[32];
	struct stack *stack;
	LIST_ENTRY(pthread) threads;
	TAILQ_ENTRY(pthread) waiting;
	pthread_cond_t blocking_cond;
	struct pthread_attr attr;
	struct rthread_storage *local_storage;
	struct rthread_cleanup_fn *cleanup_fns;

	/* cancel received in a delayed cancel block? */
	int delayed_cancel;
};
/* flags in pthread->flags */
#define	THREAD_DONE		0x001
#define	THREAD_DETACHED		0x002

/* flags in tib->tib_thread_flags */
#define	TIB_THREAD_ASYNC_CANCEL		0x001
#define	TIB_THREAD_INITIAL_STACK	0x002	/* has stack from exec */

#define ENTER_DELAYED_CANCEL_POINT(tib, self)				\
	(self)->delayed_cancel = 0;					\
	ENTER_CANCEL_POINT_INNER(tib, 1, 1)

/*
 * Internal functions exported from libc's thread bits for use by libpthread
 */
void	_spinlock(volatile _atomic_lock_t *);
int	_spinlocktry(volatile _atomic_lock_t *);
void	_spinunlock(volatile _atomic_lock_t *);

void	_rthread_debug(int, const char *, ...)
		__attribute__((__format__ (printf, 2, 3)));
pid_t	_thread_dofork(pid_t (*_sys_fork)(void));
void	_thread_finalize(void);

/*
 * Threading syscalls not declared in system headers
 */
void	__threxit(pid_t *);
int		__thrsleep(const volatile void *, clockid_t,
		    const struct timespec *, volatile void *, const int *);
int		__thrwakeup(const volatile void *, int n);
int		__thrsigdivert(sigset_t, siginfo_t *, const struct timespec *);

#endif /* _THREAD_PRIVATE_H_ */
