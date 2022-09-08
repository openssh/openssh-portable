/* CC0 license applied, see LICENCE.md */

#include <string.h>
#include "num.h"

#ifdef WITH_OPENSSL
#if OPENSSL_VERSION_NUMBER >= 0x30000000UL

typedef enum { BIG = 1, LITTLE = -1 }  endian_t;
typedef enum { NEGATIVE = 0xff, POSITIVE = 0x00 } sign_t;

static endian_t nativeendian(void)
{
    const int endiantest = 1;

    return *((char *)&endiantest) == 1 ? LITTLE : BIG;
}

static sign_t paramsign(const OSSL_PARAM *param)
{
    size_t srcmsb = nativeendian() == BIG ? 0 : param->data_size - 1;

    return
        param->data_type == OSSL_PARAM_UNSIGNED_INTEGER
        ? POSITIVE
        : (((unsigned char *)param->data)[srcmsb] & 0x80
           ? NEGATIVE
           : POSITIVE);
}

struct numdesc {
    void *data;
    unsigned int data_type;     /* The OSSL_PARAM data type */

    /* These fields concern the whole number */
    size_t size;
    endian_t endian;
    sign_t sign;

    /* These fields concern the limbs of the number */
    size_t limbsize;
    endian_t limbendian;
    /* This is for odd archs. */
    /* see the manual for mpz_import() for an in depth explanation. */
    size_t limbnailbits;
};

struct resultdesc {
    size_t size;
    int result;                 /* 1 or (negative) error */
};

static struct resultdesc provnum_copy(struct numdesc dest, struct numdesc src)
{
    struct resultdesc result = { dest.size, 1, };

    if (src.data_type != OSSL_PARAM_INTEGER
        && src.data_type != OSSL_PARAM_UNSIGNED_INTEGER) {
        result.result = PROVNUM_E_WRONG_TYPE;
        return result;
    }

    if (src.size == 0) {
        memset(dest.data, 0, dest.size);
        return result;
    }

    /* Extra data */
    size_t srcmsb = src.endian == BIG ? 0 : src.size - 1;
    int srcmsb2lsb = src.endian == BIG ? 1 : -1;

    /*
     * If the source is bigger than the destination, analyse to see if the
     * most significant byte is just padding that can be ignored.
     * The rules to determine if the most significant byte is just padding
     * are:
     *
     * 1. the most significant byte equals srcsigned, which just so happens
     *    to have the 2's complement padding value.
     * 2. The most significant bit of the next to most significant byte
     *    equals the most significant bit of srcsigned.
     */
    size_t end = dest.data == NULL ? 1 : dest.size;
    for (; src.size > end; srcmsb += srcmsb2lsb, src.size--)
        if (((unsigned char *)src.data)[srcmsb] != src.sign
            || ((((unsigned char *)src.data)[srcmsb + srcmsb2lsb] & 0x80)
                != (src.sign & 0x80)))
            break;

    if (src.size > dest.size) {
        result.result = PROVNUM_E_TOOBIG;
        return result;
    }

    size_t srclsb = srcmsb + srcmsb2lsb * (src.size - 1);

    /* Simple case, all significant details match */
    if (dest.endian == src.endian
        && dest.limbsize == 1
        && dest.limbnailbits == 0
        && (dest.data_type == OSSL_PARAM_INTEGER || src.sign == POSITIVE)) {

        if (src.size < dest.size) {
            size_t padstart = dest.endian == BIG ? 0 : dest.size - src.size;

            memset((unsigned char *)dest.data + padstart, src.sign,
                   dest.size - src.size);
        }

        size_t deststart = dest.endian == BIG ? dest.size - src.size : 0;
        size_t srcstart = src.endian == BIG ? srcmsb : srclsb;

        memcpy((unsigned char *)dest.data + deststart,
               (unsigned char *)src.data + srcstart,
               src.size);
        return result;
    }

    /* Complex case, for sign or limb conversion.  Currently unsupported */
    result.result = PROVNUM_E_UNSUPPORTED;
    return result;
}

#define implement_provnum(T, DT)                                \
    int provnum_get_##T(T *dest, const OSSL_PARAM *param)       \
    {                                                           \
        endian_t endian = nativeendian();                       \
        struct numdesc destnd = {                               \
            dest, DT, sizeof(T), endian, POSITIVE, 1, endian, 0 \
        };                                                      \
        struct numdesc srcnd = {                                \
            param->data, param->data_type, param->data_size,    \
            endian, paramsign(param), 1, endian, 0              \
        };                                                      \
                                                                \
        struct resultdesc result = provnum_copy(destnd, srcnd); \
        return result.result;                                   \
    }                                                           \
    int provnum_set_##T(OSSL_PARAM *param, T src)         \
    {                                                           \
        endian_t endian = nativeendian();                       \
        struct numdesc destnd = {                               \
            param->data, param->data_type, param->data_size,    \
            endian, POSITIVE, 1, endian, 0                      \
        };                                                      \
        struct numdesc srcnd = {                                \
            &src, DT, sizeof(T), endian, POSITIVE, 1, endian, 0 \
        };                                                      \
                                                                \
        struct resultdesc result = provnum_copy(destnd, srcnd); \
        param->return_size = result.size;                       \
        return result.result;                                   \
    }

implement_provnum(size_t, OSSL_PARAM_UNSIGNED_INTEGER)

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000UL */
#endif /* WITH_OPENSSL */
