#ifndef _STRLCPY_H
#define _STRLCPY_H

#include "config.h"
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif /* !HAVE_STRLCPY */

#endif /* _STRLCPY_H */
