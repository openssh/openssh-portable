/* $Id: getopt.h,v 1.3 2001/09/17 21:34:34 tim Exp $ */

#ifndef _GETOPT_H
#define _GETOPT_H

#include "config.h"

#ifndef HAVE_GETOPT_H

int BSDgetopt(int argc, char * const *argv, const char *opts);

#endif

#endif /* _GETOPT_H */
