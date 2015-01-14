/*
 * Copyright (c) 2015 Damien Miller <djm@mindrot.org>
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
#include <string.h>
#include <stdlib.h>

#include "bitmap.h"

#define BITMAP_WTYPE	u_int
#define BITMAP_MAX	(1<<24)
#define BITMAP_BYTES	(sizeof(BITMAP_WTYPE))
#define BITMAP_BITS	(sizeof(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
struct bitmap {
	BITMAP_WTYPE *d;
	size_t len; /* number of words allocated */
	size_t top; /* index of top word allocated */
};

struct bitmap *
bitmap_new(void)
{
	struct bitmap *ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;
	if ((ret->d = calloc(1, BITMAP_BYTES)) == NULL) {
		free(ret);
		return NULL;
	}
	ret->len = 1;
	ret->top = 0;
	return ret;
}

void
bitmap_free(struct bitmap *b)
{
	if (b != NULL && b->d != NULL) {
		memset(b->d, 0, b->len);
		free(b->d);
	}
	free(b);
}

void
bitmap_zero(struct bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_BYTES);
	b->top = 0;
}

int
bitmap_test_bit(struct bitmap *b, u_int n)
{
	if (b->top >= b->len)
		return 0; /* invalid */
	if (b->len == 0 || (n / BITMAP_BITS) > b->top)
		return 0;
	return (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

static int
reserve(struct bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	if (b->top >= b->len || n > BITMAP_MAX)
		return -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	if (b->len < nlen) {
		if ((tmp = reallocarray(b->d, nlen, BITMAP_BYTES)) == NULL)
			return -1;
		b->d = tmp;
		memset(b->d + b->len, 0, (nlen - b->len) * BITMAP_BYTES);
		b->len = nlen;
	}
	return 0;
}

int
bitmap_set_bit(struct bitmap *b, u_int n)
{
	int r;
	size_t offset;

	if ((r = reserve(b, n)) != 0)
		return r;
	offset = n / BITMAP_BITS;
	if (offset > b->top)
		b->top = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	return 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
static void
retop(struct bitmap *b)
{
	if (b->top >= b->len)
		return;
	while (b->top > 0 && b->d[b->top] == 0)
		b->top--;
}

void
bitmap_clear_bit(struct bitmap *b, u_int n)
{
	size_t offset;

	if (b->top >= b->len || n > BITMAP_MAX)
		return; /* invalid */
	offset = n / BITMAP_BITS;
	if (offset > b->top)
		return;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

size_t
bitmap_nbits(struct bitmap *b)
{
	size_t bits;
	BITMAP_WTYPE w;

	retop(b);
	if (b->top >= b->len)
		return 0; /* invalid */
	if (b->len == 0 || (b->top == 0 && b->d[0] == 0))
		return 0;
	/* Find MSB set */
	w = b->d[b->top];
	bits = (b->top + 1) * BITMAP_BITS;
	while (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	return bits;
			
}

size_t
bitmap_nbytes(struct bitmap *b)
{
	return (bitmap_nbits(b) + 7) / 8;
}

int
bitmap_to_string(struct bitmap *b, void *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	if (l < need || b->top >= b->len)
		return -1;
	if (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	for (i = k = 0; i < b->top + 1; i++) {
		for (j = 0; j < BITMAP_BYTES; j++) {
			if (k >= l)
				break;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
		
	return 0;
}

int
bitmap_from_string(struct bitmap *b, const void *p, size_t l)
{
	int r;
	size_t i, offset, shift;
	u_char *s = (u_char *)p;

	if (l > BITMAP_MAX / 8)
		return -1;
	if ((r = reserve(b, l * 8)) != 0)
		return r;
	bitmap_zero(b);
	if (l == 0)
		return 0;
	b->top = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	for (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		if (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} else
			shift -= 8;
	}
	retop(b);
	return 0;
}

#ifdef BITMAP_TEST

/* main() test against OpenSSL BN */
#include <err.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdarg.h>

#define LIM 131
#define FAIL(...) fail(__FILE__, __LINE__, __VA_ARGS__)

void
bitmap_dump(struct bitmap *b, FILE *f)
{
	size_t i;

	fprintf(f, "bitmap %p len=%zu top=%zu d =", b, b->len, b->top);
	for (i = 0; i < b->len; i++) {
		fprintf(f, " %0*llx", (int)BITMAP_BITS / 4,
		    (unsigned long long)b->d[i]);
	}
	fputc('\n', f);
}

static void
fail(char *file, int line, char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s:%d ", file, line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stdout);
	/* abort(); */
	exit(1);
}

static void
dump(const char *s, const u_char *buf, size_t l)
{
	size_t i;

	fprintf(stderr, "%s len %zu = ", s, l);
	for (i = 0; i < l; i++)
		fprintf(stderr, "%02x ", buf[i]);
	fputc('\n', stderr);
}

int main(void) {
	struct bitmap *b = bitmap_new();
	BIGNUM *bn = BN_new();
	size_t len;
	int i, j, k, n;
	u_char bbuf[1024], bnbuf[1024];
	int r;

	for (i = -1; i < LIM; i++) {
		fputc('i', stdout);
		fflush(stdout);
		for (j = -1; j < LIM; j++) {
			for (k = -1; k < LIM; k++) {
				bitmap_zero(b);
				BN_clear(bn);
				/* Test setting bits */
				if (i > 0 && bitmap_set_bit(b, i) != 0)
					FAIL("bitmap_set_bit %d fail", i);
				if (j > 0 && bitmap_set_bit(b, j) != 0)
					FAIL("bitmap_set_bit %d fail", j);
				if (k > 0 && bitmap_set_bit(b, k) != 0)
					FAIL("bitmap_set_bit %d fail", k);
				if ((i > 0 && BN_set_bit(bn, i) != 1) ||
				    (j > 0 && BN_set_bit(bn, j) != 1) ||
				    (k > 0 && BN_set_bit(bn, k) != 1))
					FAIL("BN_set_bit fail");
				for (n = 0; n < LIM; n++) {
					if (BN_is_bit_set(bn, n) !=
					    bitmap_test_bit(b, n)) {
						FAIL("miss %d/%d/%d %d "
						    "%d %d", i, j, k, n,
						    BN_is_bit_set(bn, n),
						    bitmap_test_bit(b, n));
					}
				}
				/* Test length calculations */
				if (BN_num_bytes(bn) != (int)bitmap_nbytes(b)) {
					FAIL("bytes %d/%d/%d %d != %zu",
					    i, j, k, BN_num_bytes(bn),
					    bitmap_nbytes(b));
				}
				if (BN_num_bits(bn) != (int)bitmap_nbits(b)) {
					FAIL("bits %d/%d/%d %d != %zu",
					    i, j, k, BN_num_bits(bn),
					    bitmap_nbits(b));
				}
				/* Test serialisation */
				len = bitmap_nbytes(b);
				memset(bbuf, 0xfc, sizeof(bbuf));
				if (bitmap_to_string(b, bbuf,
				    sizeof(bbuf)) != 0)
					FAIL("bitmap_to_string %d/%d/%d",
					    i, j, k);
				for (n = len; n < (int)sizeof(bbuf); n++) {
					if (bbuf[n] != 0xfc)
						FAIL("bad string "
						    "%d/%d/%d %d 0x%02x",
						    i, j, k, n, bbuf[n]);
				}
				if ((r = BN_bn2bin(bn, bnbuf)) < 0)
					FAIL("BN_bn2bin %d/%d/%d",
					    i, j, k);
				if ((size_t)r != len)
					FAIL("len bad %d/%d/%d", i, j, k);
				if (memcmp(bbuf, bnbuf, len) != 0) {
					dump("bbuf", bbuf, sizeof(bbuf));
					dump("bnbuf", bnbuf, sizeof(bnbuf));
					FAIL("buf bad %d/%d/%d", i, j, k);
				}
				/* Test deserialisation */
				bitmap_zero(b);
				if (bitmap_from_string(b, bnbuf, len) != 0)
					FAIL("bitmap_to_string %d/%d/%d",
					    i, j, k);
				for (n = 0; n < LIM; n++) {
					if (BN_is_bit_set(bn, n) !=
					    bitmap_test_bit(b, n)) {
						FAIL("miss %d/%d/%d %d "
						    "%d %d", i, j, k, n,
						    BN_is_bit_set(bn, n),
						    bitmap_test_bit(b, n));
					}
				}
				/* Test clearing bits */
				for (n = 0; n < LIM; n++) {
					if (bitmap_set_bit(b, n) != 0) {
						bitmap_dump(b, stderr);
						FAIL("bitmap_set_bit %d "
						    "fail", n);
					}
					if (BN_set_bit(bn, n) != 1)
						FAIL("BN_set_bit fail");
				}
				if (i > 0) {
					bitmap_clear_bit(b, i);
					BN_clear_bit(bn, i);
				}
				if (j > 0) {
					bitmap_clear_bit(b, j);
					BN_clear_bit(bn, j);
				}
				if (k > 0) {
					bitmap_clear_bit(b, k);
					BN_clear_bit(bn, k);
				}
				for (n = 0; n < LIM; n++) {
					if (BN_is_bit_set(bn, n) !=
					    bitmap_test_bit(b, n)) {
						bitmap_dump(b, stderr);
						FAIL("cmiss %d/%d/%d %d "
						    "%d %d", i, j, k, n,
						    BN_is_bit_set(bn, n),
						    bitmap_test_bit(b, n));
					}
				}
			}
		}
	}
	fputc('\n', stdout);
	bitmap_free(b);
	BN_free(bn);

	return 0;
}
#endif
