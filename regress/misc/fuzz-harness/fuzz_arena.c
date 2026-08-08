/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Per-iteration allocation arena for fuzz harnesses.
 *
 * Intercepts malloc / calloc / realloc / free / strdup via linker
 * --wrap and tracks every live allocation made between
 * fuzz_arena_begin() and the next release or cleanup call.
 *
 * Exit semantics:
 * - fuzz_arena_release(): stop tracking, leave allocations in place.
 *   Use when the code under test owns its allocations across iterations.
 * - fuzz_arena_cleanup(): free every still-tracked allocation. Use on
 *   longjmp recovery or when the code under test is treated as a pure
 *   per-iteration scratch user.
 *
 * Tracking is disabled outside of a begin/release-or-cleanup window
 * so libFuzzer's own bookkeeping allocations are not touched. The
 * implementation is single-threaded.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void *__real_realloc(void *, size_t);
extern void __real_free(void *);
extern char *__real_strdup(const char *);

struct arena_node {
	void *ptr;
	struct arena_node *next;
};

static struct arena_node *arena_head;
static int tracking;

static inline void
arena_track(void *p)
{
	struct arena_node *n;
	if (!tracking || p == NULL)
		return;
	n = (struct arena_node *)__real_malloc(sizeof(*n));
	if (n == NULL)
		return;
	n->ptr = p;
	n->next = arena_head;
	arena_head = n;
}

static inline void
arena_untrack(void *p)
{
	struct arena_node **pp;
	if (p == NULL)
		return;
	for (pp = &arena_head; *pp != NULL; pp = &(*pp)->next) {
		if ((*pp)->ptr == p) {
			struct arena_node *n = *pp;
			*pp = n->next;
			__real_free(n);
			return;
		}
	}
}

void *
__wrap_malloc(size_t size)
{
	void *p = __real_malloc(size);
	arena_track(p);
	return p;
}

void *
__wrap_calloc(size_t nmemb, size_t size)
{
	void *p = __real_calloc(nmemb, size);
	arena_track(p);
	return p;
}

void *
__wrap_realloc(void *ptr, size_t size)
{
	arena_untrack(ptr);
	void *p = __real_realloc(ptr, size);
	arena_track(p);
	return p;
}

void
__wrap_free(void *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

char *
__wrap_strdup(const char *s)
{
	size_t len;
	char *p;
	if (s == NULL)
		return NULL;
	len = strlen(s) + 1;
	p = (char *)__real_malloc(len);
	if (p == NULL)
		return NULL;
	memcpy(p, s, len);
	arena_track(p);
	return p;
}

void
fuzz_arena_begin(void)
{
	tracking = 1;
}

void
fuzz_arena_release(void)
{
	struct arena_node *n;
	tracking = 0;
	while (arena_head != NULL) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n);
	}
}

void
fuzz_arena_cleanup(void)
{
	struct arena_node *n;
	tracking = 0;
	while (arena_head != NULL) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n->ptr);
		__real_free(n);
	}
}
