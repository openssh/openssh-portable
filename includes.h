/*	$OpenBSD: includes.h,v 1.15 2001/06/08 15:25:40 markus Exp $	*/

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file includes most of the needed system headers.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef INCLUDES_H
#define INCLUDES_H

#define RCSID(msg) \
static /**/const char *const rcsid[] = { (char *)rcsid, "\100(#)" msg }

#include "config.h"

#include "openbsd-compat/bsd-nextstep.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/utsname.h>

#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <dirent.h>

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif
#ifndef HAVE_GETOPT_OPTRESET
#define getopt(ac, av, o)  BSDgetopt(ac, av, o)
#endif
#ifdef HAVE_BSTRING_H
# include <bstring.h>
#endif
#if defined(HAVE_GLOB_H) && defined(GLOB_HAS_ALTDIRFUNC) && \
    defined(GLOB_HAS_GL_MATCHC)
# include <glob.h>
#endif
#ifdef HAVE_NETGROUP_H
# include <netgroup.h>
#endif
#if defined(HAVE_NETDB_H)
# include <netdb.h>
#endif
#ifdef HAVE_ENDIAN_H
# include <endian.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_BSDTTY_H
# include <sys/bsdtty.h>
#endif
#ifdef HAVE_TTYENT_H
# include <ttyent.h>
#endif
#ifdef USE_PAM
# include <security/pam_appl.h>
#endif
#ifdef HAVE_POLL_H
# include <poll.h>
#else
# ifdef HAVE_SYS_POLL_H
#  include <sys/poll.h>
# endif
#endif
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>
#endif
#ifdef HAVE_UTIME_H
# include <utime.h>
#endif
#include "version.h"
#include "openbsd-compat/openbsd-compat.h"
#include "openbsd-compat/bsd-cygwin_util.h"
#include "entropy.h"

#endif /* INCLUDES_H */
