/*
 *   base-64 encoding pinched from lynx2-7-2, who pinched it from rpem.
 *   Originally written by Mark Riordan 12 August 1990 and 17 Feb 1991
 *   and placed in the public domain.
 *
 *   Dug Song <dugsong@UMICH.EDU>
 */

#include "includes.h"
#include "xmalloc.h"

char six2pr[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

unsigned char pr2six[256];

int
uuencode(unsigned char *bufin, unsigned int nbytes, char *bufcoded)
{
	/* ENC is the basic 1 character encoding function to make a char printing */
#define ENC(c) six2pr[c]

	register char *outptr = bufcoded;
	unsigned int i;

	for (i = 0; i < nbytes; i += 3) {
		*(outptr++) = ENC(*bufin >> 2);						/* c1 */
		*(outptr++) = ENC(((*bufin << 4) & 060)   | ((bufin[1] >> 4) & 017));	/* c2 */
		*(outptr++) = ENC(((bufin[1] << 2) & 074) | ((bufin[2] >> 6) & 03));	/* c3 */
		*(outptr++) = ENC(bufin[2] & 077);					/* c4 */
		bufin += 3;
	}
	if (i == nbytes + 1) {
		outptr[-1] = '=';
	} else if (i == nbytes + 2) {
		outptr[-1] = '=';
		outptr[-2] = '=';
	} else if (i == nbytes) {
		*(outptr++) = '=';
	}
	*outptr = '\0';
	return (outptr - bufcoded);
}

int
uudecode(const char *bufcoded, unsigned char *bufplain, int outbufsize)
{
	/* single character decode */
#define DEC(c) pr2six[(unsigned char)c]
#define MAXVAL 63

	static int first = 1;
	int nbytesdecoded, j;
	const char *bufin = bufcoded;
	register unsigned char *bufout = bufplain;
	register int nprbytes;

	/* If this is the first call, initialize the mapping table. */
	if (first) {
		first = 0;
		for (j = 0; j < 256; j++)
			pr2six[j] = MAXVAL + 1;
		for (j = 0; j < 64; j++)
			pr2six[(unsigned char) six2pr[j]] = (unsigned char) j;
	}
	/* Strip leading whitespace. */
	while (*bufcoded == ' ' || *bufcoded == '\t')
		bufcoded++;

	/*
	 * Figure out how many characters are in the input buffer. If this
	 * would decode into more bytes than would fit into the output
	 * buffer, adjust the number of input bytes downwards.
	 */
	bufin = bufcoded;
	while (DEC(*(bufin++)) <= MAXVAL)
		;
	nprbytes = bufin - bufcoded - 1;
	nbytesdecoded = ((nprbytes + 3) / 4) * 3;
	if (nbytesdecoded > outbufsize)
		nprbytes = (outbufsize * 4) / 3;

	bufin = bufcoded;

	while (nprbytes > 0) {
		*(bufout++) = (unsigned char) (DEC(*bufin)   << 2 | DEC(bufin[1]) >> 4);
		*(bufout++) = (unsigned char) (DEC(bufin[1]) << 4 | DEC(bufin[2]) >> 2);
		*(bufout++) = (unsigned char) (DEC(bufin[2]) << 6 | DEC(bufin[3]));
		bufin += 4;
		nprbytes -= 4;
	}
	if (nprbytes & 03) {
		if (DEC(bufin[-2]) > MAXVAL)
			nbytesdecoded -= 2;
		else
			nbytesdecoded -= 1;
	}
	return (nbytesdecoded);
}

void
dump_base64(FILE *fp, unsigned char *data, int len)
{
	unsigned char *buf = xmalloc(2*len);
	int i, n;
	n = uuencode(data, len, buf);
	for (i = 0; i < n; i++) {
		fprintf(fp, "%c", buf[i]);
		if (i % 70 == 69)
			fprintf(fp, "\n");
	}
	if (i % 70 != 69)
		fprintf(fp, "\n");
	xfree(buf);
}
