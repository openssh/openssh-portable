/*
 * Defines and prototypes specific to NeXT system
 */

#ifndef _NEXT_POSIX_H
#define _NEXT_POSIX_H

#ifdef HAVE_NEXT

#include <libc.h>
#include <sys/dir.h>

/* FILE */
#define O_NONBLOCK      00004   /* non-blocking open */

/* WAITPID */
#undef WIFEXITED
#undef WIFSTOPPED
#undef WIFSIGNALED

#define _W_INT(w)			(*(int*)&(w))	/* convert union wait to int */
#define WIFEXITED(w)		(!((_W_INT(w)) & 0377))
#define WIFSTOPPED(w)	((_W_INT(w)) & 0100)
#define WIFSIGNALED(w)	(!WIFEXITED(x) && !WIFSTOPPED(x))
#define WEXITSTATUS(w)	(int)(WIFEXITED(x) ? ((_W_INT(w) >> 8) & 0377) : -1)
#define WTERMSIG(w)		(int)(WIFSIGNALED(x) ? (_W_INT(w) & 0177) : -1)
#define WCOREFLAG			0x80
#define WCOREDUMP(w)		((_W_INT(w)) & WCOREFLAG)

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

/* Sig*() */
typedef sigset_t;
#define SIG_BLOCK		00
#define SIG_UNBLOCK	01
#define SIG_SETMASK	02
#define SA_RESTART	00
struct sigaction {
	void			(*sa_handler)();
	sigset_t		sa_mask;
	int			sa_flags;
};

int sigemptyset(sigset_t *set);
int sigaddset(sigset_t *set, int signum);
int sigprocmask(int  how,  const  sigset_t *set, sigset_t *oldset);
int sigsuspend(const sigset_t *mask);
int sigaction(int signum,const struct sigaction *act, struct sigaction *oldact); 

#endif /* HAVE_NEXT */

#endif /* _NEXT_POSIX_H */
