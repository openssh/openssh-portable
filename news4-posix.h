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

/* WAITPID */
#undef WIFEXITED
#undef WIFSTOPPED
#undef WIFSIGNALED

#define _W_INT(w)	(*(int*)&(w))	/* convert union wait to int */
#define WIFEXITED(w)	(!((_W_INT(w)) & 0377))
#define WIFSTOPPED(w)	((_W_INT(w)) & 0100)
#define WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
#define WEXITSTATUS(w)	(int)(WIFEXITED(w) ? ((_W_INT(w) >> 8) & 0377) : -1)
#define WTERMSIG(w)	(int)(WIFSIGNALED(w) ? (_W_INT(w) & 0177) : -1)
#define WCOREFLAG	0x80
#define WCOREDUMP(w) 	((_W_INT(w)) & WCOREFLAG)

int waitpid(int pid,int *stat_loc,int options);
#define setsid() setpgrp(0, getpid())

#endif /* HAVE_NEWS4 */
#endif /* _NEWS4_POSIX_H */
