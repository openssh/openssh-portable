/* $Id: getusershell.h,v 1.1 2001/03/18 23:09:28 djm Exp $ */

#ifndef _GETUSERSHELL_H
#define _GETUSERSHELL_H

#include "config.h"

#ifndef HAVE_GETUSERSHELL

char *getusershell(void);
void setusershell(void);
void endusershell(void);

#endif /* HAVE_GETUSERSHELL */

#endif /* _GETUSERSHELL_H */
