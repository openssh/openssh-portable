#ifndef _BSD_STRSEP_H
#define _BSD_STRSEP_H

#include "config.h"

#ifndef HAVE_STRSEP
char *strsep(char **stringp, const char *delim);
#endif /* HAVE_STRSEP */

#endif /* _BSD_STRSEP_H */
