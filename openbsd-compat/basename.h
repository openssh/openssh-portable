/* $Id: basename.h,v 1.2 2003/02/24 23:25:12 djm Exp $ */

#ifndef _BASENAME_H 
#define _BASENAME_H
#include "config.h"

#if !defined(HAVE_BASENAME)

char *basename(char *path);

#endif /* !defined(HAVE_BASENAME) */
#endif /* _BASENAME_H */
