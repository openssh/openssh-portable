/*

mpaux.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun Jul 16 04:29:30 1995 ylo

This file contains various auxiliary functions related to multiple
precision integers.

*/

#include "includes.h"
RCSID("$Id: mpaux.c,v 1.6 1999/11/16 02:37:16 damien Exp $");

#ifdef HAVE_OPENSSL
#include <openssl/bn.h>
#include <openssl/md5.h>
#endif
#ifdef HAVE_SSL
#include <ssl/bn.h>
#include <ssl/md5.h>
#endif

#include "getput.h"
#include "xmalloc.h"


void
compute_session_id(unsigned char session_id[16],
		   unsigned char cookie[8],
		   BIGNUM *host_key_n,
		   BIGNUM *session_key_n)
{
  unsigned int host_key_bits = BN_num_bits(host_key_n);
  unsigned int session_key_bits = BN_num_bits(session_key_n);
  unsigned int bytes = (host_key_bits + 7) / 8 + (session_key_bits + 7) / 8 + 8;
  unsigned char *buf = xmalloc(bytes);
  MD5_CTX md;

  BN_bn2bin(host_key_n, buf);
  BN_bn2bin(session_key_n, buf + (host_key_bits + 7 ) / 8);
  memcpy(buf + (host_key_bits + 7) / 8 + (session_key_bits + 7) / 8,
	 cookie, 8);
  MD5_Init(&md);
  MD5_Update(&md, buf, bytes);
  MD5_Final(session_id, &md);
  memset(buf, 0, bytes);
  xfree(buf);
}
