/* $OpenBSD: roaming_common.c,v 1.4 2009/06/21 09:04:03 dtucker Exp $ */
/*
 * Copyright (c) 2004-2009 AppGate Network Security AB
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <unistd.h>

#include "atomicio.h"
#include "log.h"
#include "packet.h"
#include "xmalloc.h"
#include "cipher.h"
#include "buffer.h"
#include "roaming.h"

static u_int64_t write_bytes = 0;
static u_int64_t read_bytes = 0;

int resume_in_progress = 0;

u_int64_t
get_recv_bytes(void)
{
	return read_bytes;
}

void
add_recv_bytes(u_int64_t num)
{
	read_bytes += num;
}

u_int64_t
get_sent_bytes(void)
{
	return write_bytes;
}

void
roam_set_bytes(u_int64_t sent, u_int64_t recvd)
{
	read_bytes = recvd;
	write_bytes = sent;
}

ssize_t
roaming_write(int fd, const void *buf, size_t count, int *cont)
{
	ssize_t ret;

	ret = write(fd, buf, count);
	if (ret > 0 && !resume_in_progress) {
		write_bytes += ret;
	}
	debug3("Wrote %ld bytes for a total of %llu", (long)ret,
	    (unsigned long long)write_bytes);
	return ret;
}

ssize_t
roaming_read(int fd, void *buf, size_t count, int *cont)
{
	ssize_t ret = read(fd, buf, count);
	if (ret > 0) {
		if (!resume_in_progress) {
			read_bytes += ret;
		}
	}
	return ret;
}

size_t
roaming_atomicio(ssize_t(*f)(int, void*, size_t), int fd, void *buf,
    size_t count)
{
	size_t ret = atomicio(f, fd, buf, count);

	if (f == vwrite && ret > 0 && !resume_in_progress) {
		write_bytes += ret;
	} else if (f == read && ret > 0 && !resume_in_progress) {
		read_bytes += ret;
	}
	return ret;
}
