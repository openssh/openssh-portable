#ifndef _MKTEMP_H
#define _MKTEMP_H

#include "config.h"
#ifndef HAVE_MKDTEMP
int mkstemps(char *path, int slen);
int mkstemp(char *path);
char *mkdtemp(char *path);
#endif /* !HAVE_MKDTEMP */

#endif /* _MKTEMP_H */
