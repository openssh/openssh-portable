#ifndef _BSD_INET_NTOA_H
#define _BSD_INET_NTOA_H

#include "config.h"

#if defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
char *inet_ntoa(struct in_addr in);
#endif /* defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA) */

#endif /* _BSD_INET_NTOA_H */
