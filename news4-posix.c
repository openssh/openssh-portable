#include "config.h"

#ifdef HAVE_NEWS4
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
#include "news4-posix.h"

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

#endif /* HAVE_NEWS4 */
