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
#include <fcntl.h>
#include <io.h>

int binary_open(const char *filename, int flags, mode_t mode)
{
       return open(filename, flags | O_BINARY, mode);
}

int binary_pipe(int fd[2])
{
       int ret = pipe(fd);
       if (!ret) {
               setmode (fd[0], O_BINARY);
               setmode (fd[1], O_BINARY);
       }
}
#endif
