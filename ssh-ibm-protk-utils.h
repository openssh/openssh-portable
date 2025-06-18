/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef __s390x__

#include "includes.h"

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

#include "openbsd-compat/openssl-compat.h"

// Size of WK VP block appended to a prot key
#define IBM_PROTK_AES_WK_VP_SIZE 32

struct kdsa_entry_s {
	int keytype;
	int nid;
	int sign_enc_fc;
	int fsize;  // field size in param block
	int d_size; // the real priv key size
};

static inline int s390_kdsa(unsigned long func, void *param,
			    const unsigned char *src, unsigned long srclen)
{
	register unsigned long r0 asm("0") = (unsigned long)func;
	register unsigned long r1 asm("1") = (unsigned long)param;
	register unsigned long r2 asm("2") = (unsigned long)src;
	register unsigned long r3 asm("3") = (unsigned long)srclen;
	unsigned long rc = 1;

	asm volatile(
		 "0:	.insn	rre,%[__opc] << 16,0,%[__src]\n"
		 "	brc	1,0b\n"
		 "	lghi	%[__rc],0\n"
		 "	brc	8,1f\n"
		 "	lghi	%[__rc],1\n"
		 "	brc	4,1f\n"
		 "	lghi	%[__rc],2\n"
		 "1:\n"
		 : [__src] "+a" (r2), [__srclen] "+d" (r3), [__rc] "+d" (rc)
		 : [__fc] "d" (r0), [__param] "a" (r1), [__opc] "i" (0xb93a)
		 : "cc", "memory");

	return (int) rc;
}

const struct kdsa_entry_s *find_kdsa_entry(int kt, int nid);

#endif /* s390x Architecture */
