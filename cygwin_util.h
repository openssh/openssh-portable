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

#include "config.h"

#ifdef HAVE_CYGWIN

int binary_open(const char *filename, int flags, ...);
int binary_pipe(int fd[2]);
int check_nt_auth(int pwd_authenticated, uid_t uid);
int check_ntsec(const char *filename);

#define open binary_open
#define pipe binary_pipe

#endif /* HAVE_CYGWIN */
