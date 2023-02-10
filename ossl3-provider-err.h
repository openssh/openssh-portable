/* CC0 license applied, see LICENCE.md */

#include "includes.h"
#ifdef WITH_OPENSSL
#if OPENSSL_VERSION_NUMBER >= 0x30000000UL
#include <stdint.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>

/*
 * The idea with this library is to replace OpenSSL's ERR_raise() and
 * ERR_raise_data() with variants that are more suitable for providers that
 * have their own error reason table.
 *
 * This assumes variadic function-like macros, i.e. C99 or newer.
 *
 * A minimal amount of preparation is needed on provider initialization and
 * takedown:
 *
 * 1.  The provider's outgoing OSSL_DISPATCH table must include an entry
 *     got OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, with a function that returns
 *     the provider's table of reasons.
 *     That table of reasons is a simple OSSL_ITEM array, where each element
 *     contains a numeric reason identity for the reason, and the description
 *     text string for that reason.
 *     Each numeric reason identity MUST be unique within this array.
 *
 * 2.  On provider initialization, an error handle must be created using
 *     proverr_new_handle().  The returned pointer is passed as first argument
 *     to ERR_raise() and ERR_raise_data().
 *
 * 3.  On provider takedown, the error handle must be freed, using
 *     proverr_free_handle().
 *
 * With this preparation, the provider code can use ERR_raise() and
 * ERR_raise_data() "as usual", with the exception that the first argument is
 * the error handle instead of one of the OpenSSL ERR_LIB_ macros.
 */

/*
 * In case <openssl/err.h> was included, we throw away its error recording
 * macros.
 * Note that ERR_put_error() is NOT recreated.  It's deprecated and should not
 * be used any more.
 */
#undef ERR_put_error
#undef ERR_raise
#undef ERR_raise_data

#define ERR_raise(handle, reason) ERR_raise_data((handle),(reason),NULL)

#define ERR_raise_data(handle, reason, ...)                                 \
  (proverr_new_error(handle),                                               \
   proverr_set_error_debug(handle, OPENSSL_FILE,OPENSSL_LINE,OPENSSL_FUNC), \
   proverr_set_error(handle, reason, __VA_ARGS__))

/*
 * The structure where the libcrypto core handle and core functions are
 * captured.
 */
struct proverr_functions_st;

struct proverr_functions_st *
proverr_new_handle(const OSSL_CORE_HANDLE *core, const OSSL_DISPATCH *in);
struct proverr_functions_st *
proverr_dup_handle(struct proverr_functions_st *src);
void proverr_free_handle(struct proverr_functions_st *handle);

void proverr_new_error(const struct proverr_functions_st *handle);
void proverr_set_error_debug(const struct proverr_functions_st *handle,
                             const char *file, int line, const char *func);
void proverr_set_error(const struct proverr_functions_st *handle,
                       uint32_t reason, const char *fmt, ...);
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000UL */
#endif /* WITH_OPENSSL */
