#ifndef UUENCODE_H
#define UUENCODE_H
int	uuencode(unsigned char *bufin, unsigned int nbytes, char *bufcoded);
int	uudecode(const char *bufcoded, unsigned char *bufplain, int outbufsize);
void	dump_base64(FILE *fp, unsigned char *data, int len);
#endif
