/* CC0 license applied, see LICENCE.md */

#include <assert.h>
#include <stdlib.h>
#include "err.h"

#ifdef WITH_OPENSSL
#if OPENSSL_VERSION_NUMBER >= 0x30000000UL

struct proverr_functions_st {
  const OSSL_CORE_HANDLE *core;
  OSSL_FUNC_core_new_error_fn *core_new_error;
  OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug;
  OSSL_FUNC_core_vset_error_fn *core_vset_error;
};

struct proverr_functions_st *
proverr_new_handle(const OSSL_CORE_HANDLE *core, const OSSL_DISPATCH *dispatch)
{
  /*
   * libcrypto gives providers the tools to create error routines similar
   * to the ones defined in <openssl/err.h>
   */
  OSSL_FUNC_core_new_error_fn *c_new_error = NULL;
  OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug = NULL;
  OSSL_FUNC_core_vset_error_fn *c_vset_error = NULL;
  struct proverr_functions_st *handle = NULL;

  assert(core != NULL);
  assert(dispatch != NULL);

#ifndef DEBUG
  if (core == NULL || dispatch == NULL)
    return NULL;
#endif

  for (; dispatch->function_id != 0; dispatch++)
    switch (dispatch->function_id) {
    case OSSL_FUNC_CORE_NEW_ERROR:
      c_new_error = OSSL_FUNC_core_new_error(dispatch);
      break;
    case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
      c_set_error_debug = OSSL_FUNC_core_set_error_debug(dispatch);
      break;
    case OSSL_FUNC_CORE_VSET_ERROR:
      c_vset_error = OSSL_FUNC_core_vset_error(dispatch);
      break;
    }

  assert(c_new_error != NULL);
  assert(c_set_error_debug != NULL);
  assert(c_vset_error != NULL);

#ifdef NDEBUG
  if (c_new_error == NULL || c_set_error_debug == NULL || c_vset_error == NULL)
    return NULL;
#endif

  if ((handle = malloc(sizeof(*handle))) != NULL) {
    handle->core = core;
    handle->core_new_error = c_new_error;
    handle->core_set_error_debug = c_set_error_debug;
    handle->core_vset_error = c_vset_error;
  }
  return handle;
}

struct proverr_functions_st *
proverr_dup_handle(struct proverr_functions_st *src)
{
  struct proverr_functions_st *dst = NULL;

  if (src != NULL
      && (dst = malloc(sizeof(*dst))) != NULL) {
    dst->core = src->core;
    dst->core_new_error = src->core_new_error;
    dst->core_set_error_debug = src->core_set_error_debug;
    dst->core_vset_error = src->core_vset_error;
  }
  return dst;
}

void proverr_free_handle(struct proverr_functions_st *handle)
{
  free(handle);
}

void proverr_new_error(const struct proverr_functions_st *handle)
{
  handle->core_new_error(handle->core);
}

void proverr_set_error_debug(const struct proverr_functions_st *handle,
                             const char *file, int line, const char *func)
{
  handle->core_set_error_debug(handle->core, file, line, func);
}

void proverr_set_error(const struct proverr_functions_st *handle,
                       uint32_t reason, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  handle->core_vset_error(handle->core, reason, fmt, ap);
  va_end(ap);
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000UL */
#endif /* WITH_OPENSSL */
