/* $Id: bsd-snprintf.h,v 1.3 2003/05/18 14:13:39 djm Exp $ */

#ifndef _BSD_SNPRINTF_H
#define _BSD_SNPRINTF_H

#include "config.h"

#include <sys/types.h> /* For size_t */

#ifndef HAVE_SNPRINTF
int snprintf(char *, size_t, const char *, ...);
#endif /* !HAVE_SNPRINTF */

#ifndef HAVE_VSNPRINTF
int vsnprintf(char *, size_t, const char *, va_list);
#endif /* !HAVE_SNPRINTF */


#endif /* _BSD_SNPRINTF_H */
