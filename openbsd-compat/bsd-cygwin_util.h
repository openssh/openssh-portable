/*
 *
 * cygwin_util.c
 *
 * Author: Corinna Vinschen <vinschen@cygnus.com>
 *
 * Copyright (c) 2000 Corinna Vinschen <vinschen@cygnus.com>, Duisburg, Germany
 *                    All rights reserved
 *
 * Created: Sat Sep 02 12:17:00 2000 cv
 *
 * This file contains functions for forcing opened file descriptors to
 * binary mode on Windows systems.
 */

/* $Id: bsd-cygwin_util.h,v 1.5 2001/11/27 01:19:44 tim Exp $ */

#ifndef _BSD_CYGWIN_UTIL_H
#define _BSD_CYGWIN_UTIL_H

#ifdef HAVE_CYGWIN

#include <io.h>

int binary_open(const char *filename, int flags, ...);
int binary_pipe(int fd[2]);
int check_nt_auth(int pwd_authenticated, uid_t uid);
int check_ntsec(const char *filename);
void register_9x_service(void);

#define open binary_open
#define pipe binary_pipe

#endif /* HAVE_CYGWIN */

#endif /* _BSD_CYGWIN_UTIL_H */
