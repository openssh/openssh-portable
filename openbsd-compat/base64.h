/* $Id: base64.h,v 1.5 2003/05/15 03:57:51 djm Exp $ */

#ifndef _BSD_BASE64_H
#define _BSD_BASE64_H

#include "config.h"

#ifndef HAVE___B64_NTOP
# ifndef HAVE_B64_NTOP
int b64_ntop(u_char const *src, size_t srclength, char *target, 
    size_t targsize);
# endif /* !HAVE_B64_NTOP */
# define __b64_ntop(a,b,c,d) b64_ntop(a,b,c,d)
#endif /* HAVE___B64_NTOP */

#ifndef HAVE___B64_PTON
# ifndef HAVE_B64_PTON
int b64_pton(char const *src, u_char *target, size_t targsize);
# endif /* !HAVE_B64_PTON */
# define __b64_pton(a,b,c) b64_pton(a,b,c)
#endif /* HAVE___B64_PTON */

#endif /* _BSD_BASE64_H */
