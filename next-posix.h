/*
 * Defines and prototypes specific to NeXT system
 */

#ifndef _NEXT_POSIX_H
#define _NEXT_POSIX_H

#ifdef HAVE_NEXT

#include <libc.h>
#include <sys/dir.h>

/* readdir() returns struct direct (BSD) not struct dirent (POSIX) */
#define dirent direct                                                

/* POSIX utime() struct */
struct utimbuf {
	time_t  actime;
	time_t  modtime;
};

/* FILE */
#define O_NONBLOCK      00004   /* non-blocking open */

/* WAITPID */
#undef WIFEXITED
#undef WIFSTOPPED
#undef WIFSIGNALED

#define WIFEXITED(w)	(!((w) & 0377))
#define WIFSTOPPED(w)	((w) & 0100)
#define WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
#define WEXITSTATUS(w)	(int)(WIFEXITED(w) ? ((w >> 8) & 0377) : -1)
#define WTERMSIG(w)	(int)(WIFSIGNALED(w) ? (w & 0177) : -1)
#define WCOREFLAG	0x80
#define WCOREDUMP(w) 	((w) & WCOREFLAG)

/* POSIX "wrapper" functions to replace to BSD functions */
int posix_utime(char *filename, struct utimbuf *buf);	/* new utime() */
#define utime posix_utime

pid_t posix_wait(int *status);				/* new wait() */
#define wait posix_wait	

/* MISC functions */
int waitpid(int pid,int *stat_loc,int options);
#define getpgrp()	getpgrp(0)
pid_t setsid(void);

/* TC */
int tcgetattr(int fd,struct termios *t);
int tcsetattr(int fd,int opt,const struct termios *t);
int tcsetpgrp(int fd, pid_t pgrp);
speed_t cfgetospeed(const struct termios *t);
speed_t cfgetispeed(const struct termios *t);
int cfsetospeed(struct termios *t,int speed);


#endif /* HAVE_NEXT */
#endif /* _NEXT_POSIX_H */
