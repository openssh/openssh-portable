#ifndef _BSD_SNPRINTF_H
#define _BSD_SNPRINTF_H

#include "config.h"

#include <sys/types.h> /* For size_t */

#ifndef HAVE_SNPRINTF
int snprintf(char *str, size_t n, char const *fmt, ...);
#endif /* !HAVE_SNPRINTF */

#ifndef HAVE_VSNPRINTF
int vsnprintf(char *str, size_t n, char *fmt, va_list *ap);
#endif /* !HAVE_SNPRINTF */


#endif /* _BSD_SNPRINTF_H */
