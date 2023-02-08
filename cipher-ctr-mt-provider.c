/*
 * OpenSSH Multi-threaded AES-CTR Cipher Provider for OpenSSL 3
 *
 * Author: Chris Rapier <rapier@psc.edu>
 * Copyright (c) 2022 Pittsburgh Supercomputing Center. All rights reserved.
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

/* based on vienere.c from https://github.com/provider-corner/vigenere by
 * Richard Levitte provided under a CC0 Public License. */

#include "includes.h"

#ifdef WITH_OPENSSL
/* only for systems with OSSL 3.0+ */
#if OPENSSL_VERSION_NUMBER >= 0x30000000UL

#include <sys/types.h>
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include "xmalloc.h"
#include "err.h"
#include "num.h"
#include "cipher-ctr-mt-functions.h"

#define ERR_HANDLE(ctx) ((ctx)->provctx->proverr_handle)

/* forward declartion of cipher functions */
/* cipher context functions */
OSSL_FUNC_cipher_newctx_fn aes_mt_newctx_256;
OSSL_FUNC_cipher_newctx_fn aes_mt_newctx_192;
OSSL_FUNC_cipher_newctx_fn aes_mt_newctx_128;
OSSL_FUNC_cipher_freectx_fn aes_mt_freectx;

/* param related function*/
static OSSL_FUNC_cipher_get_params_fn aes_mt_get_params_256;
static OSSL_FUNC_cipher_get_params_fn aes_mt_get_params_192;
static OSSL_FUNC_cipher_get_params_fn aes_mt_get_params_128;
static OSSL_FUNC_cipher_gettable_params_fn aes_mt_gettable_params;
static OSSL_FUNC_cipher_set_ctx_params_fn aes_mt_set_ctx_params;
static OSSL_FUNC_cipher_get_ctx_params_fn aes_mt_get_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn aes_mt_settable_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn aes_mt_gettable_ctx_params;

/* en/decipher functions */
OSSL_FUNC_cipher_encrypt_init_fn aes_mt_start_threads;
OSSL_FUNC_cipher_decrypt_init_fn aes_mt_start_threads;
OSSL_FUNC_cipher_update_fn aes_mt_do_cipher;

/* provider context */
static OSSL_FUNC_provider_query_operation_fn aes_mt_prov_query;
static OSSL_FUNC_provider_get_reason_strings_fn aes_mt_prov_reasons;
static OSSL_FUNC_provider_teardown_fn aes_mt_prov_teardown;
static OSSL_FUNC_provider_get_params_fn aes_mt_prov_get_params; 
OSSL_provider_init_fn OSSL_provider_init; /* need this? */

/* error functions */
OSSL_FUNC_core_new_error_fn *c_new_error;
OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
OSSL_FUNC_core_vset_error_fn *c_vset_error;
OSSL_FUNC_core_set_error_mark_fn *c_set_error_mark;
OSSL_FUNC_core_clear_last_error_mark_fn *c_clear_last_error_mark;
OSSL_FUNC_core_pop_error_to_mark_fn *c_pop_error_to_mark;

/* Errors used in this provider */
#define AES_MT_E_MALLOC           1
#define AES_MT_ONGOING_OPERATION  2
#define AES_MT_BAD_KEYLEN         3

/* typedef for function pointers */
typedef void(*fptr_t)(void);

/* all of the various arrays we need */

/* BAD_KEYLEN isn't being used at the moment */
const OSSL_ITEM reasons[] = {
	{ AES_MT_E_MALLOC, "Memory allocation failure" },
	{ AES_MT_ONGOING_OPERATION, "Operation underway" },
	{ AES_MT_BAD_KEYLEN, "Only 256, 192, and 128 Key lengths are supported" },
	{ 0, NULL } /* Termination */
};

/* function mapping for 256|192|128 key lengths */
const OSSL_DISPATCH aes_mt_funcs_256[] = {
	{ OSSL_FUNC_CIPHER_NEWCTX, (fptr_t)aes_mt_newctx_256 } ,
	{ OSSL_FUNC_CIPHER_FREECTX, (fptr_t)aes_mt_freectx },
	{ OSSL_FUNC_CIPHER_ENCRYPT_INIT, (fptr_t)aes_mt_start_threads },
	{ OSSL_FUNC_CIPHER_DECRYPT_INIT, (fptr_t)aes_mt_start_threads },
	{ OSSL_FUNC_CIPHER_UPDATE, (fptr_t)aes_mt_do_cipher },
	{ OSSL_FUNC_CIPHER_GET_PARAMS, (fptr_t)aes_mt_get_params_256 },
	{ OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (fptr_t)aes_mt_gettable_params },
	{ OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (fptr_t)aes_mt_get_ctx_params },
	{ OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
	  (fptr_t)aes_mt_gettable_ctx_params },
	{ OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (fptr_t)aes_mt_set_ctx_params },
	{ OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
	  (fptr_t)aes_mt_settable_ctx_params },
	{ 0, NULL }
};

const OSSL_DISPATCH aes_mt_funcs_192[] = {
	{ OSSL_FUNC_CIPHER_NEWCTX, (fptr_t)aes_mt_newctx_192 } ,
	{ OSSL_FUNC_CIPHER_FREECTX, (fptr_t)aes_mt_freectx },
	{ OSSL_FUNC_CIPHER_ENCRYPT_INIT, (fptr_t)aes_mt_start_threads },
	{ OSSL_FUNC_CIPHER_DECRYPT_INIT, (fptr_t)aes_mt_start_threads },
	{ OSSL_FUNC_CIPHER_UPDATE, (fptr_t)aes_mt_do_cipher },
	{ OSSL_FUNC_CIPHER_GET_PARAMS, (fptr_t)aes_mt_get_params_192 },
	{ OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (fptr_t)aes_mt_gettable_params },
	{ OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (fptr_t)aes_mt_get_ctx_params },
	{ OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
	  (fptr_t)aes_mt_gettable_ctx_params },
	{ OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (fptr_t)aes_mt_set_ctx_params },
	{ OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
	  (fptr_t)aes_mt_settable_ctx_params },
	{ 0, NULL }
};

const OSSL_DISPATCH aes_mt_funcs_128[] = {
	{ OSSL_FUNC_CIPHER_NEWCTX, (fptr_t)aes_mt_newctx_128 } ,
	{ OSSL_FUNC_CIPHER_FREECTX, (fptr_t)aes_mt_freectx },
	{ OSSL_FUNC_CIPHER_ENCRYPT_INIT, (fptr_t)aes_mt_start_threads },
	{ OSSL_FUNC_CIPHER_DECRYPT_INIT, (fptr_t)aes_mt_start_threads },
	{ OSSL_FUNC_CIPHER_UPDATE, (fptr_t)aes_mt_do_cipher },
	{ OSSL_FUNC_CIPHER_GET_PARAMS, (fptr_t)aes_mt_get_params_128 },
	{ OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (fptr_t)aes_mt_gettable_params },
	{ OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (fptr_t)aes_mt_get_ctx_params },
	{ OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
	  (fptr_t)aes_mt_gettable_ctx_params },
	{ OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (fptr_t)aes_mt_set_ctx_params },
	{ OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
	  (fptr_t)aes_mt_settable_ctx_params },
	{ 0, NULL }
};

/* the ciphers found in this provider */
const OSSL_ALGORITHM aes_mt_ciphers[] = {
	{ "aes_ctr_mt_256", "provider=hpnssh", aes_mt_funcs_256 },
	{ "aes_ctr_mt_192", "provider=hpnssh", aes_mt_funcs_192 },
	{ "aes_ctr_mt_128", "provider=hpnssh", aes_mt_funcs_128 },
	{ NULL, NULL, NULL }
};

/* function mapping for provider methods */
const OSSL_DISPATCH provider_functions[] = {
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (fptr_t)aes_mt_prov_teardown },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (fptr_t)aes_mt_prov_query },
	{ OSSL_FUNC_PROVIDER_GET_PARAMS, (fptr_t)aes_mt_prov_get_params },
	{ OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (fptr_t)aes_mt_prov_reasons },
	{ 0, NULL }
};

static const OSSL_PARAM ctx_get_param_table[] = {
        { "keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
};

static const OSSL_PARAM cipher_get_param_table[] = {
        { "blocksize", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { "keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
};

static const OSSL_PARAM cipher_set_param_table[] = {
	{ "keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
	{ NULL, 0, NULL, 0, 0 },
};


/* provider functions start here */

static void provider_ctx_free(struct provider_ctx_st *ctx)
{
    if (ctx != NULL)
        proverr_free_handle(ctx->proverr_handle);
    free(ctx);
}

static struct provider_ctx_st *provider_ctx_new(const OSSL_CORE_HANDLE *core,
                                                const OSSL_DISPATCH *in)
{
    struct provider_ctx_st *ctx;

    if ((ctx = malloc(sizeof(*ctx))) != NULL
        && (ctx->proverr_handle = proverr_new_handle(core, in)) != NULL) {
        ctx->core_handle = core;
    } else {
        provider_ctx_free(ctx);
        ctx = NULL;
    }
    return ctx;
}


/* returns the appropriate algo table for the requested function
 * in this case we should only be working with OP_CIPHER */
const OSSL_ALGORITHM *aes_mt_prov_query(void *provctx, int operation_id,
				     int *no_store)
{
	switch (operation_id) {
	case OSSL_OP_CIPHER:
		return aes_mt_ciphers;
	}
	return NULL;
}

const OSSL_ITEM *aes_mt_prov_reasons(void *provctx)
{
	return reasons;
}

static int aes_mt_prov_get_params(void *provctx, OSSL_PARAM *params)
{
	OSSL_PARAM *p;
	int ok = 1;

	char *VERSION="1.0";
	char *BUILDTYPE="aes_ctr_mt@hpnssh.org";
	
	for(p = params; p->key != NULL; p++)
		if (strcasecmp(p->key, "version") == 0) {
			*(const void **)p->data = VERSION;
			p->return_size = strlen(VERSION);
		} else if (strcasecmp(p->key, "buildinfo") == 0
			   && BUILDTYPE[0] != '\0') {
			*(const void **)p->data = BUILDTYPE;
			p->return_size = strlen(BUILDTYPE);
		}
	return ok;
}

/* The function that tears down this provider */
static void aes_mt_prov_teardown(void *vprovctx)
{
    provider_ctx_free(vprovctx);
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
		       const OSSL_DISPATCH *in,
		       const OSSL_DISPATCH **out,
		       void **vprovctx)
{
    if ((*vprovctx = provider_ctx_new(core, in)) == NULL)
	    return 0;
    *out = provider_functions;
    return 1;
}

/* parameter functions for 256|192|128 bit key lengths */
static int aes_mt_get_params_256(OSSL_PARAM params[])
{
	OSSL_PARAM *p;
	int ok = 1;
	
	for (p = params; p->key != NULL; p++) {
		if (strcasecmp(p->key, "blocksize") == 0)
			if (provnum_set_size_t(p, AES_BLOCK_SIZE) < 0) {
				ok = 0;
				continue;
			}
		if (strcasecmp(p->key, "keylen") == 0) {
			size_t keyl = 32;
			
			if (provnum_set_size_t(p, keyl) < 0) {
				ok = 0;
				continue;
			}
		}
	}
	return ok;
}

static int aes_mt_get_params_192(OSSL_PARAM params[])
{
	OSSL_PARAM *p;
	int ok = 1;
	
	for (p = params; p->key != NULL; p++) {
		if (strcasecmp(p->key, "blocksize") == 0)
			if (provnum_set_size_t(p, AES_BLOCK_SIZE) < 0) {
				ok = 0;
				continue;
			}
		if (strcasecmp(p->key, "keylen") == 0) {
			size_t keyl = 24;
			
			if (provnum_set_size_t(p, keyl) < 0) {
				ok = 0;
				continue;
			}
		}
	}
	return ok;
}

static int aes_mt_get_params_128(OSSL_PARAM params[])
{
	OSSL_PARAM *p;
	int ok = 1;
	
	for (p = params; p->key != NULL; p++) {
		if (strcasecmp(p->key, "blocksize") == 0)
			if (provnum_set_size_t(p, AES_BLOCK_SIZE) < 0) {
				ok = 0;
				continue;
			}
		if (strcasecmp(p->key, "keylen") == 0) {
			size_t keyl = 16;
			
			if (provnum_set_size_t(p, keyl) < 0) {
				ok = 0;
				continue;
			}
		}
	}
	return ok;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *aes_mt_gettable_params(void *provctx)
{
	return cipher_get_param_table;
}

static const OSSL_PARAM *aes_mt_gettable_ctx_params(void *cctx, void *provctx)
{
	return ctx_get_param_table;
}

static int aes_mt_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct aes_mt_ctx_st *ctx = vctx;
    int ok = 1;

    if (ctx->keylen > 0) {
        OSSL_PARAM *p;

        for (p = params; p->key != NULL; p++)
            if (strcasecmp(p->key, "keylen") == 0
                && provnum_set_size_t(p, ctx->keylen) < 0) {
                ok = 0;
                continue;
            }
    }
    return ok;
}

/* Parameters that libcrypto can send to this implementation */
static const OSSL_PARAM *aes_mt_settable_ctx_params(void *cctx, void *provctx)
{
    return cipher_set_param_table;
}

static int aes_mt_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct aes_mt_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;
    int ok = 1;

    if (ctx->ongoing) {
        ERR_raise(ERR_HANDLE(ctx), AES_MT_ONGOING_OPERATION);
        return 0;
    }

    for (p = params; p->key != NULL; p++)
        if (strcasecmp(p->key, "keylen") == 0) {
            size_t keyl = 0;

            if (provnum_get_size_t(&keyl, p) < 0) {
                ok = 0;
                continue;
            }
            ctx->keylen = keyl;
        }
    return ok;
}

#endif /*OPENSSL_VERSION_NUMBER */
#endif /*WITH_OPENSSL*/
