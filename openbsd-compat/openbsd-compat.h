/* $Id: openbsd-compat.h,v 1.8 2001/06/25 08:09:17 djm Exp $ */

#ifndef _OPENBSD_H
#define _OPENBSD_H

#include "config.h"

/* OpenBSD function replacements */
#include "bindresvport.h"
#include "getcwd.h"
#include "realpath.h"
#include "rresvport.h"
#include "strlcpy.h"
#include "strlcat.h"
#include "strmode.h"
#include "mktemp.h"
#include "daemon.h"
#include "dirname.h"
#include "base64.h"
#include "sigact.h"
#include "inet_aton.h"
#include "inet_ntoa.h"
#include "inet_ntop.h"
#include "strsep.h"
#include "strtok.h"
#include "vis.h"
#include "setproctitle.h"
#include "getgrouplist.h"
#include "glob.h"
#include "getusershell.h"
#include "readpassphrase.h"

/* Home grown routines */
#include "bsd-arc4random.h"
#include "bsd-misc.h"
#include "bsd-snprintf.h"
#include "bsd-waitpid.h"

/* rfc2553 socket API replacements */
#include "fake-getaddrinfo.h"
#include "fake-getnameinfo.h"
#include "fake-socket.h"

#endif /* _OPENBSD_H */
