#ifndef CHACHA_POLY_LIBCRYPTO_MT_H
#define CHACHA_POLY_LIBCRYPTO_MT_H

#include <sys/types.h>
#include "chacha.h"
#include "poly1305.h"
#include "cipher-chachapoly.h"

struct chachapoly_ctx *chachapoly_new_mt(struct chachapoly_ctx * oldctx, const u_char *key, u_int keylen)
    __attribute__((__bounded__(__buffer__, 2, 3)));
void chachapoly_free_mt(struct chachapoly_ctx *cpctx);

int	chachapoly_crypt_mt(struct chachapoly_ctx *cpctx, u_int seqnr,
    u_char *dest, const u_char *src, u_int len, u_int aadlen, u_int authlen,
    int do_encrypt);
int	chachapoly_get_length_mt(struct chachapoly_ctx *cpctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
    __attribute__((__bounded__(__buffer__, 4, 5)));

#endif /* CHACHA_POLY_LIBCRYPTO_MT_H */
