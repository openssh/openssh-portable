/* $OpenBSD: ed25519.c,v 1.3 2013/12/09 11:03:45 markus Exp $ */

/*
 * Public Domain, Authors: Daniel J. Bernstein, Niels Duif, Tanja Lange,
 * Peter Schwabe, Bo-Yin Yang.
 * Copied from supercop-20130419/crypto_sign/ed25519/ref/ed25519.c
 */

#include "includes.h"
#include "crypto_api.h"

#ifdef USING_WOLFSSL
#include "key.h"
#include <wolfssl/openssl/ed25519.h>
#else
#include "ge25519.h"
#endif

#ifndef USING_WOLFSSL
static void get_hram(unsigned char *hram, const unsigned char *sm, const unsigned char *pk, unsigned char *playground, unsigned long long smlen)
{
  unsigned long long i;

  for (i =  0;i < 32;++i)    playground[i] = sm[i];
  for (i = 32;i < 64;++i)    playground[i] = pk[i-32];
  for (i = 64;i < smlen;++i) playground[i] = sm[i];

  crypto_hash_sha512(hram,playground,smlen);
}
#else
/* only for compilation issue: cross reference of crypto_hash_sha512 in
 * libssh and libopenbsd-compat */
void wolfssl_unused()
{
    crypto_hash_sha512(NULL,NULL,0);
}
#endif


int crypto_sign_ed25519_keypair(
    unsigned char *pk,
    unsigned char *sk
    )
{
#ifdef USING_WOLFSSL
  int ret, pksize = ED25519_PK_SZ, sksize = ED25519_SK_SZ;

  ret = wolfSSL_ED25519_generate_key(sk, &sksize, pk, &pksize);
  if (ret != 1 || sksize != ED25519_SK_SZ || pksize != ED25519_PK_SZ)
      fatal("%s: wolfSSL_ED25519_generate_key failed", __func__);
#else
  sc25519 scsk;
  ge25519 gepk;
  unsigned char extsk[64];
  int i;

  randombytes(sk, 32);
  crypto_hash_sha512(extsk, sk, 32);
  extsk[0] &= 248;
  extsk[31] &= 127;
  extsk[31] |= 64;

  sc25519_from32bytes(&scsk,extsk);

  ge25519_scalarmult_base(&gepk, &scsk);
  ge25519_pack(pk, &gepk);
  for(i=0;i<32;i++)
    sk[32 + i] = pk[i];
#endif /* USING_WOLFSSL */

    return 0;
}

int crypto_sign_ed25519(
    unsigned char *sm,unsigned long long *smlen,
    const unsigned char *m,unsigned long long mlen,
    const unsigned char *sk
    )
{
#ifdef USING_WOLFSSL
  int ret;

  ret = wolfSSL_ED25519_sign(m, mlen, sk, ED25519_SK_SZ,
                             sm, (unsigned int *)smlen);
  if (ret != 1 || *smlen != 64)
      fatal("%s: wolfSSL_ED25519_sign failed", __func__);

  /* add message in the signature buffer */
  memcpy(sm+(*smlen), m, mlen);
  *smlen += mlen;

#else
  sc25519 sck, scs, scsk;
  ge25519 ger;
  unsigned char r[32];
  unsigned char s[32];
  unsigned char extsk[64];
  unsigned long long i;
  unsigned char hmg[crypto_hash_sha512_BYTES];
  unsigned char hram[crypto_hash_sha512_BYTES];

  crypto_hash_sha512(extsk, sk, 32);
  extsk[0] &= 248;
  extsk[31] &= 127;
  extsk[31] |= 64;

  *smlen = mlen+64;
  for(i=0;i<mlen;i++)
    sm[64 + i] = m[i];
  for(i=0;i<32;i++)
    sm[32 + i] = extsk[32+i];

  crypto_hash_sha512(hmg, sm+32, mlen+32); /* Generate k as h(extsk[32],...,extsk[63],m) */

  /* Computation of R */
  sc25519_from64bytes(&sck, hmg);
  ge25519_scalarmult_base(&ger, &sck);
  ge25519_pack(r, &ger);

  /* Computation of s */
  for(i=0;i<32;i++)
    sm[i] = r[i];

  get_hram(hram, sm, sk+32, sm, mlen+64);

  sc25519_from64bytes(&scs, hram);
  sc25519_from32bytes(&scsk, extsk);
  sc25519_mul(&scs, &scs, &scsk);

  sc25519_add(&scs, &scs, &sck);

  sc25519_to32bytes(s,&scs); /* cat s */
  for(i=0;i<32;i++)
    sm[32 + i] = s[i];
#endif /* USING_WOLFSSL */
  return 0;
}

int crypto_sign_ed25519_open(
    unsigned char *m,unsigned long long *mlen,
    const unsigned char *sm,unsigned long long smlen,
    const unsigned char *pk
    )
{
    unsigned int i;
    int ret;

#ifdef USING_WOLFSSL
    ret = wolfSSL_ED25519_verify(sm+ED25519_SIG_SZ, smlen-ED25519_SIG_SZ, pk, ED25519_PK_SZ, sm, ED25519_SIG_SZ);
    if (ret != 1) {
        debug("%s: wolfSSL_ED25519_verify failed", __func__);
        ret = 1;
    }
    else
        ret = 0;
#else
  unsigned char t2[32];
  ge25519 get1, get2;
  sc25519 schram, scs;
  unsigned char hram[crypto_hash_sha512_BYTES];

  *mlen = (unsigned long long) -1;
  if (smlen < 64) return -1;

  if (ge25519_unpackneg_vartime(&get1, pk)) return -1;

  get_hram(hram,sm,pk,m,smlen);

  sc25519_from64bytes(&schram, hram);

  sc25519_from32bytes(&scs, sm+32);

  ge25519_double_scalarmult_vartime(&get2, &get1, &schram, &ge25519_base, &scs);
  ge25519_pack(t2, &get2);

  ret = crypto_verify_32(sm, t2);
#endif /* USING_WOLFSSL */

  /* return message included in signature buffer */
  if (!ret)
  {
    for(i=0;i<smlen-64;i++)
      m[i] = sm[i + 64];
    *mlen = smlen-64;
  }
  else
  {
    for(i=0;i<smlen-64;i++)
      m[i] = 0;
  }
  return ret;
}
