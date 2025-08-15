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

#include "ssh-ibm-protk-utils.h"

static const struct kdsa_entry_s kdsa_info[] = {
	{ KEY_ECDSA,   NID_X9_62_prime256v1, 17, 32, 32 },  // P256
	{ KEY_ECDSA,          NID_secp384r1, 18, 48, 48 },  // P384
	{ KEY_ECDSA,          NID_secp521r1, 19, 80, 66 },  // P521
	{ KEY_ED25519,                    0, 48, 32, 32 },  // Ed25519
	{ 0,                              0,  0,  0,  0 }   // NULL
};

const struct kdsa_entry_s *find_kdsa_entry(int kt, int nid)
{
	const struct kdsa_entry_s *p;

	for (p = kdsa_info; p->keytype; p++)
		if (p->nid == nid && p->keytype == kt)
			return (const struct kdsa_entry_s *) p;

	return NULL;
}

#endif /* s390x Architecture */
