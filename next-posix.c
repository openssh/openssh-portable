#include "config.h"

#ifdef HAVE_NEXT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/file.h>
#include <errno.h>
#include <termios.h>
#include <sys/wait.h>

#include "xmalloc.h"
#include "ssh.h"
#include "next-posix.h"

int
waitpid(int	pid, int	*stat_loc, int	options)
{
	if (pid <= 0) {
		if (pid != -1) {
			errno = EINVAL;
			return -1;
		}
		pid = 0;	/* wait4() expects pid=0 for indiscriminate wait. */
	}
	return wait4(pid, (union wait *)stat_loc, options, NULL);
}

pid_t setsid(void)
{
	return setpgrp(0, getpid());
}

int
tcgetattr(int fd, struct termios *t)
{
	return (ioctl(fd, TIOCGETA, t));
}

int
tcsetattr(int fd, int opt, const struct termios *t)
{
	struct termios localterm;

	if (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	switch (opt & ~TCSASOFT) {
	case TCSANOW:
		return (ioctl(fd, TIOCSETA, t));
	case TCSADRAIN:
		return (ioctl(fd, TIOCSETAW, t));
	case TCSAFLUSH:
		return (ioctl(fd, TIOCSETAF, t));
	default:
		errno = EINVAL;
		return (-1);
	}
}

int tcsetpgrp(int fd, pid_t pgrp)
{
	int s;

	s = pgrp;
	return (ioctl(fd, TIOCSPGRP, &s));
}

speed_t cfgetospeed(const struct termios *t)
{
	return (t->c_ospeed);
}

speed_t cfgetispeed(const struct termios *t)
{
	return (t->c_ispeed);
}

int
cfsetospeed(struct termios *t,int speed)
{
	t->c_ospeed = speed;
	return (0);
}

int
cfsetispeed(struct termios *t, int speed)
{
	t->c_ispeed = speed;
	return (0);
}
#endif /* HAVE_NEXT */
