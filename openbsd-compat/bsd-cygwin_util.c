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

#include "includes.h"

RCSID("$Id: bsd-cygwin_util.c,v 1.4 2001/04/13 14:28:42 djm Exp $");

#ifdef HAVE_CYGWIN

#include <fcntl.h>
#include <stdlib.h>
#include <sys/vfs.h>
#include <windows.h>
#define is_winnt       (GetVersion() < 0x80000000)

#if defined(open) && open == binary_open
# undef open
#endif
#if defined(pipe) && open == binary_pipe
# undef pipe
#endif

int binary_open(const char *filename, int flags, ...)
{
	va_list ap;
	mode_t mode;
	
	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	return open(filename, flags | O_BINARY, mode);
}

int binary_pipe(int fd[2])
{
	int ret = pipe(fd);

	if (!ret) {
		setmode (fd[0], O_BINARY);
		setmode (fd[1], O_BINARY);
	}
	return ret;
}

int check_nt_auth(int pwd_authenticated, uid_t uid)
{
	/*
	* The only authentication which is able to change the user
	* context on NT systems is the password authentication. So
	* we deny all requsts for changing the user context if another
	* authentication method is used.
	* This may change in future when a special openssh
	* subauthentication package is available.
	*/
	if (is_winnt && !pwd_authenticated && geteuid() != uid)
		return 0;
	
	return 1;
}

int check_ntsec(const char *filename)
{
	char *cygwin;
	int allow_ntea = 0;
	int allow_ntsec = 0;
	struct statfs fsstat;

	/* Windows 95/98/ME don't support file system security at all. */
	if (!is_winnt)
		return 0;

	/* Evaluate current CYGWIN settings. */
	if ((cygwin = getenv("CYGWIN")) != NULL) {
		if (strstr(cygwin, "ntea") && !strstr(cygwin, "nontea"))
			allow_ntea = 1;
		if (strstr(cygwin, "ntsec") && !strstr(cygwin, "nontsec"))
			allow_ntsec = 1;
	}

	/*
	 * `ntea' is an emulation of POSIX attributes. It doesn't support
	 * real file level security as ntsec on NTFS file systems does
	 * but it supports FAT filesystems. `ntea' is minimum requirement
	 * for security checks.
	 */
	if (allow_ntea)
		return 1;

	/*
	 * Retrieve file system flags. In Cygwin, file system flags are
	 * copied to f_type which has no meaning in Win32 itself.
	 */
	if (statfs(filename, &fsstat))
		return 1;

	/*
	 * Only file systems supporting ACLs are able to set permissions.
	 * `ntsec' is the setting in Cygwin which switches using of NTFS
	 * ACLs to support POSIX permissions on files.
	 */
	if (fsstat.f_type & FS_PERSISTENT_ACLS)
		return allow_ntsec;

	return 0;
}

#endif /* HAVE_CYGWIN */
