/*	$OpenBSD: sshbuf.c,v 1.18 2022/05/25 06:03:44 djm Exp $	*/
/*
 * Copyright (c) 2011 Damien Miller
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

#define SSHBUF_INTERNAL
#include "includes.h"

#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ssherr.h"
#include "sshbuf.h"
#include "misc.h"
/* #include "log.h" */

#define BUF_WATERSHED 256*1024

#ifdef SSHBUF_DEBUG
# define SSHBUF_TELL(what) do { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_alloc); \
		fflush(stdout); \
	} while (0)
#else
# define SSHBUF_TELL(what)
#endif

static inline int
sshbuf_check_sanity(const struct sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	if (__predict_false(buf == NULL ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == NULL ||
	    buf->max_alloc > SSHBUF_ALLOC_MAX ||
	    (!buf->readonly && (buf->max_alloc & 1) != 0) ||
	    buf->alloc > buf->max_alloc ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		raise(SIGSEGV);
		return SSH_ERR_INTERNAL_ERROR;
	}
	return 0;
}

static void
sshbuf_maybe_pack(struct sshbuf *buf, int force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	if (buf->off == 0 || buf->readonly || buf->refcount > 1)
		return;
	if (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

struct sshbuf *
sshbuf_new(void)
{
	struct sshbuf *ret;

	if ((ret = calloc(sizeof(*ret), 1)) == NULL)
		return NULL;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_alloc = SSHBUF_ALLOC_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = NULL;
	if ((ret->cd = ret->d = calloc(1, ret->alloc)) == NULL) {
		free(ret);
		return NULL;
	}
	return ret;
}

struct sshbuf *
sshbuf_from(const void *blob, size_t len)
{
	struct sshbuf *ret;

	if (blob == NULL || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(sizeof(*ret), 1)) == NULL)
		return NULL;
	ret->alloc = ret->size = ret->max_alloc = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = NULL;
	ret->cd = blob;
	ret->d = NULL;
	return ret;
}

int
sshbuf_set_parent(struct sshbuf *child, struct sshbuf *parent)
{
	int r;

	if ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		return r;
	if (child->parent != NULL && child->parent != parent)
		return SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	return 0;
}

struct sshbuf *
sshbuf_fromb(struct sshbuf *buf)
{
	struct sshbuf *ret;

	if (sshbuf_check_sanity(buf) != 0)
		return NULL;
	if ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == NULL)
		return NULL;
	if (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		return NULL;
	}
	return ret;
}

void
sshbuf_free(struct sshbuf *buf)
{
	if (buf == NULL)
		return;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	if (sshbuf_check_sanity(buf) != 0)
		return;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	if (buf->refcount > 0)
		return;

	/*
	 * If we are a child, the free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = NULL;

	if (!buf->readonly) {
		explicit_bzero(buf->d, buf->alloc);
		free(buf->d);
	}
	freezero(buf, sizeof(*buf));
}

void
sshbuf_reset(struct sshbuf *buf)
{
	u_char *d;

	if (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		return;
	}
	if (sshbuf_check_sanity(buf) != 0)
		return;
	buf->off = buf->size = 0;
	if (buf->alloc != SSHBUF_SIZE_INIT) {
		if ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != NULL) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

size_t
sshbuf_max_size(const struct sshbuf *buf)
{
	return buf->max_alloc / 2;
}

size_t
sshbuf_alloc(const struct sshbuf *buf)
{
	return buf->alloc;
}

const struct sshbuf *
sshbuf_parent(const struct sshbuf *buf)
{
	return buf->parent;
}

u_int
sshbuf_refcount(const struct sshbuf *buf)
{
	return buf->refcount;
}

int
sshbuf_set_max_size(struct sshbuf *buf, size_t requested_size)
{
	size_t rlen, max_alloc = requested_size * 2;
	u_char *dp;
	int r;

	/*
	 * Note that we set the actual allocation limit to be 2x the requested
	 * size. This is to avoid some pathological compaction behaviour later
	 * when a buffer is at capacity and has small drains/fills on it.
	 */
	SSHBUF_DBG(("set max buf = %p requested = %zu", buf, requested_size));
	if ((r = sshbuf_check_sanity(buf)) != 0)
		return r;
	if (max_alloc == buf->max_alloc)
		return 0;
	if (buf->readonly || buf->refcount > 1)
		return SSH_ERR_BUFFER_READ_ONLY;
	if (requested_size > SSHBUF_SIZE_MAX || max_alloc > SSHBUF_ALLOC_MAX)
		return SSH_ERR_NO_BUFFER_SPACE;
	/*
	 * Always pack as it makes everything that follows easier.
	 * Potentially expensive, but this should seldom be called on buffers
	 * that already contain data.
	 */
	sshbuf_maybe_pack(buf, 1);
	/* Refuse setting a maximum below current amount of data in buffer */
	if (requested_size < buf->size)
		return SSH_ERR_NO_BUFFER_SPACE;
	/* Shrink alloc if the existing allocation is larger than requested */
	if (requested_size < buf->alloc) {
		if (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		else
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		if (rlen > max_alloc)
			rlen = max_alloc;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		if ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	buf->max_alloc = max_alloc;
	return 0;
}

size_t
sshbuf_len(const struct sshbuf *buf)
{
	if (sshbuf_check_sanity(buf) != 0)
		return 0;
	return buf->size - buf->off;
}

size_t
sshbuf_avail(const struct sshbuf *buf)
{
	if (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		return 0;
	return (buf->max_alloc / 2) - (buf->size - buf->off);
}

const u_char *
sshbuf_ptr(const struct sshbuf *buf)
{
	if (sshbuf_check_sanity(buf) != 0)
		return NULL;
	return buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(const struct sshbuf *buf)
{
	if (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		return NULL;
	return buf->d + buf->off;
}

int
sshbuf_check_reserve(const struct sshbuf *buf, size_t len)
{
	int r;

	if ((r = sshbuf_check_sanity(buf)) != 0)
		return r;
	if (buf->readonly || buf->refcount > 1)
		return SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max size + available < len */
	if (len > (buf->max_alloc / 2) ||
	    (buf->max_alloc / 2) - len < buf->size - buf->off)
		return SSH_ERR_NO_BUFFER_SPACE;
	return 0;
}

int
sshbuf_allocate(struct sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	int r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	if ((r = sshbuf_check_reserve(buf, len)) != 0)
		return r;
	/*
	 * If the requested allocation appended would push us past max_alloc
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_alloc);
	SSHBUF_TELL("allocate");
	if (len + buf->size <= buf->alloc)
		return 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_alloc.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	/* With the changes in 8.9 the output buffer end up growing pretty
	 * slowly. It's knows that it needs to grow but it only does so 32K
	 * at a time. This means a lot of calls to realloc and memcpy which
	 * kills performance until the buffer reaches some maximum size.
	 * so we explicitly test for a buffer that's trying to grow and
	 * if it is then we push the growth to whatever the adjusted value of
	 * local_window_max happens to be. This significantly reduces overhead
	 * and improves performance. In this case we look for a buffer that is trying
	 * to grow larger than BUF_WATERSHED (256*1024 taken from PACKET_MAX_SIZE)
	 * and where the local_window_max isn't zero (which is usally in the Channels
	 * struct but we copied it into the shhbuf as window_max). If it is zero or
	 * the buffer is smaller than BUF_WATERSHED we just use the
	 * normal value for need. We also don't want to grow the buffer past
	 * what we need (the size of window_max) so if the current allocation (in
	 * buf->alloc) is greater than window_max we skip it.
	 */
	if (rlen > BUF_WATERSHED && buf->window_max !=0  && buf->alloc < buf->window_max) {
		/* debug_f ("%p, prior rlen %zu and need %zu buf_alloc is %zu", buf, rlen, need, buf->alloc); */
		/* set need to the the max window size less the current allocation */
		need = buf->max_alloc;
		rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
		/* debug_f ("%p, rlen is %zu need is %zu window max is %zu max_size is %zu",
		 *	 buf, rlen, need, buf->window_max, buf->max_alloc); */
	}
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));

	/* there is a buffer that needs to grow quickly but doesn't seem to count as 
	 * input or output so we check to make sure that window_max isn't set
	 * before we do. In this case we set it immediately to the maximum 
	 * allocated buffer size which shoudl be about 32MB 
	 * this likely isn't the right way to do this but it works for now
	 * TODO: Come up with a better solution -cjr 12/1/2022 */
	if (rlen > BUF_WATERSHED && buf->window_max == 0) 
		rlen = buf->max_alloc;
	/* rlen might be above the max allocation */
	if (rlen > buf->max_alloc)
		rlen = buf->max_alloc;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	if ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == NULL) {
		SSHBUF_DBG(("realloc fail"));
		return SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	if ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		return r;
	}
	SSHBUF_TELL("done");
	return 0;
}

int
sshbuf_reserve(struct sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	int r;

	if (dpp != NULL)
		*dpp = NULL;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	if ((r = sshbuf_allocate(buf, len)) != 0)
		return r;

	dp = buf->d + buf->size;
	buf->size += len;
	if (dpp != NULL)
		*dpp = dp;
	return 0;
}

int
sshbuf_consume(struct sshbuf *buf, size_t len)
{
	int r;

	SSHBUF_DBG(("len = %zu", len));
	if ((r = sshbuf_check_sanity(buf)) != 0)
		return r;
	if (len == 0)
		return 0;
	if (len > sshbuf_len(buf))
		return SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	if (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	return 0;
}

int
sshbuf_consume_end(struct sshbuf *buf, size_t len)
{
	int r;

	SSHBUF_DBG(("len = %zu", len));
	if ((r = sshbuf_check_sanity(buf)) != 0)
		return r;
	if (len == 0)
		return 0;
	if (len > sshbuf_len(buf))
		return SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	return 0;
}
