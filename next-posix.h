/*
 * Defines and prototypes specific to NeXT system
 */

#ifndef _NEXT_POSIX_H
#define _NEXT_POSIX_H

#ifdef HAVE_NEXT

#include <libc.h>
#include <sys/dir.h>

#define NAME_MAX 255
struct dirent {
	off_t   d_off;
	unsigned long   d_fileno;
	unsigned short  d_reclen;
	unsigned short  d_namlen;
	char    d_name[NAME_MAX + 1];
};

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

#define _W_INT(w)	(*(int*)&(w))	/* convert union wait to int */
#define WIFEXITED(w)	(!((_W_INT(w)) & 0377))
#define WIFSTOPPED(w)	((_W_INT(w)) & 0100)
#define WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
#define WEXITSTATUS(w)	(int)(WIFEXITED(w) ? ((_W_INT(w) >> 8) & 0377) : -1)
#define WTERMSIG(w)	(int)(WIFSIGNALED(w) ? (_W_INT(w) & 0177) : -1)
#define WCOREFLAG	0x80
#define WCOREDUMP(w) 	((_W_INT(w)) & WCOREFLAG)

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
