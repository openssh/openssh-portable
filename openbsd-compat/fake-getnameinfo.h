/* $Id: fake-getnameinfo.h,v 1.4 2003/06/04 23:48:33 djm Exp $ */

#ifndef _FAKE_GETNAMEINFO_H
#define _FAKE_GETNAMEINFO_H

#include "config.h"

#ifndef HAVE_GETNAMEINFO
int getnameinfo(const struct sockaddr *, size_t, char *, size_t, 
    char *, size_t, int);
#endif /* !HAVE_GETNAMEINFO */

#ifndef NI_NUMERICHOST
# define NI_NUMERICHOST    (1)
# define NI_NAMEREQD       (1<<1)
# define NI_NUMERICSERV    (1<<2)
#endif

#ifndef NI_MAXSERV
# define NI_MAXSERV 32
#endif /* !NI_MAXSERV */
#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif /* !NI_MAXHOST */

#endif /* _FAKE_GETNAMEINFO_H */
