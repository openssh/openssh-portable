/* $Id: getopt.h,v 1.2 2001/07/14 16:05:55 stevesk Exp $ */

#ifndef _GETOPT_H
#define _GETOPT_H

#include "config.h"

#ifndef HAVE_GETOPT_H

int getopt(int argc, char * const *argv, const char *opts);

#endif

#endif /* _GETOPT_H */
