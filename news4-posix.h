/*
 * Defines and prototypes specific to News4 system
 */

#ifndef _NEWS4_POSIX_H
#define _NEWS4_POSIX_H

#ifdef HAVE_NEWS4
#include <sys/wait.h>

typedef long	clock_t;

/* FILE */
#define O_NONBLOCK      00004   /* non-blocking open */

#endif /* HAVE_NEWS4 */
#endif /* _NEWS4_POSIX_H */
