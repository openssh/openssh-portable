#include "includes.h"
RCSID("$Id: fingerprint.c,v 1.1 1999/11/16 22:49:28 markus Exp $");

#include "ssh.h"
#include "xmalloc.h"
#include <ssl/md5.h>

#define FPRINT "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"

/* Generate key fingerprint in ascii format.
   Based on ideas and code from Bjoern Groenvall <bg@sics.se> */

char *
fingerprint(BIGNUM *e, BIGNUM *n)
{
	static char     retval[80];
	MD5_CTX         md;
	unsigned char   d[16];
	char           *buf;
	int             nlen, elen;

	nlen = BN_num_bytes(n);
	elen = BN_num_bytes(e);

	buf = xmalloc(nlen + elen);

	BN_bn2bin(n, buf);
	BN_bn2bin(e, buf + nlen);

	MD5_Init(&md);
	MD5_Update(&md, buf, nlen + elen);
	MD5_Final(d, &md);
	snprintf(retval, sizeof(retval), FPRINT,
		 d[0], d[1], d[2],  d[3],  d[4],  d[5],  d[6],  d[7],
		 d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
	memset(buf, 0, nlen + elen);
	xfree(buf);
	return retval;
}
