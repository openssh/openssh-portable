#include "oqs-utils.h"

int oqs_utils_is_rsa_hybrid(int keytype) {
    switch(keytype) {
///// OQS_TEMPLATE_FRAGMENT_LIST_RSA_HYBRIDS_START
        case KEY_RSA3072_FALCON_512:
            return 1;
        case KEY_RSA3072_DILITHIUM_2_AES:
            return 1;
        case KEY_RSA3072_SPHINCS_HARAKA_128F_SIMPLE:
            return 1;
///// OQS_TEMPLATE_FRAGMENT_LIST_RSA_HYBRIDS_END
    }
    return 0;
}

int oqs_utils_is_ecdsa_hybrid(int keytype) {
    switch(keytype) {
///// OQS_TEMPLATE_FRAGMENT_LIST_ECDSA_HYBRIDS_START
        case KEY_ECDSA_NISTP256_FALCON_512:
            return 1;
        case KEY_ECDSA_NISTP521_FALCON_1024:
            return 1;
        case KEY_ECDSA_NISTP384_DILITHIUM_3:
            return 1;
        case KEY_ECDSA_NISTP256_DILITHIUM_2_AES:
            return 1;
        case KEY_ECDSA_NISTP521_DILITHIUM_5_AES:
            return 1;
        case KEY_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE:
            return 1;
        case KEY_ECDSA_NISTP384_SPHINCS_HARAKA_192F_ROBUST:
            return 1;
///// OQS_TEMPLATE_FRAGMENT_LIST_ECDSA_HYBRIDS_END
    }
    return 0;
}

int oqs_utils_is_hybrid(int keytype) {
    return oqs_utils_is_rsa_hybrid(keytype) || oqs_utils_is_ecdsa_hybrid(keytype);
}
