#ifndef _BSD_STRTOK_H
#define _BSD_STRTOK_H

#include "config.h"

#ifndef HAVE_STRTOK_R
char *strtok_r(char *s, const char *delim, char **last);
#endif /* HAVE_STRTOK_R */

#endif /* _BSD_STRTOK_H */
