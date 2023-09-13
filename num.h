/* CC0 license applied, see LICENCE.md */

#include "includes.h"
#ifdef WITH_OPENSSL3

#include <openssl/core.h>

/* Convert between OSSL_PARAM and size_t */
int provnum_get_size_t(size_t *dest, const OSSL_PARAM *param);
int provnum_set_size_t(OSSL_PARAM *param, size_t src);

#define PROVNUM_E_WRONG_TYPE    -1
#define PROVNUM_E_TOOBIG        -2
#define PROVNUM_E_UNSUPPORTED   -3
#endif /* WITH_OPENSSL3 */
