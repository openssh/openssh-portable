/* $Id: inet_ntop.h,v 1.1 2001/04/12 21:35:53 mouring Exp $ */

#ifndef _BSD_RRESVPORT_H
#define _BSD_RRESVPORT_H

#include "config.h"

#ifndef HAVE_INET_NTOP
const char *                 
inet_ntop(int af, const void *src, char *dst, size_t size);
#endif /* !HAVE_INET_NTOP */

#endif /* _BSD_RRESVPORT_H */
