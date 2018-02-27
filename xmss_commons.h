#ifdef WITH_XMSS
/*
xmss_commons.h 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/
#ifndef XMSS_COMMONS_H
#define XMSS_COMMONS_H

#include <stdlib.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

void to_byte(unsigned char *output, unsigned long long in, uint32_t bytes);
#if 0
void hexdump(const unsigned char *a, size_t len);
#endif
#endif
#endif /* WITH_XMSS */
