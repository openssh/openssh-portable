/* $Id: getopt.h,v 1.1 2001/07/14 03:22:54 djm Exp $ */

#ifndef _GETOPT_H
#define _GETOPT_H

#include "config.h"

#ifndef HAVE_GETOPT_H

int getopt(int argc, char **argv, char *opts);

#endif

#endif /* _GETOPT_H */
