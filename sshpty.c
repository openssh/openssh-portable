/* $OpenBSD: sshpty.c,v 1.34 2019/07/04 16:20:10 deraadt Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Allocating a pseudo-terminal, and making it the controlling tty.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <signal.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#ifdef HAVE_UTIL_H
# include <util.h>
#endif
#include <unistd.h>

#include "sshpty.h"
#include "log.h"
#include "misc.h"
#include "xmalloc.h"

#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

#ifdef __APPLE__
# include <AvailabilityMacros.h>
# if (MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5)
#  define __APPLE_PRIVPTY__
# endif
#endif


#ifdef HAVE_ETC_LOGIN_DEFS

struct logindefs_entry {
	char* key, *value;
};

/*
 * Reads login definitions from a file (typically /etc/login.defs)
 * and stores them in an array for struct logindefs_entry.
 * The returned array is null-terminated.
 */

static struct logindefs_entry** read_logindefs_file(const char* filename) {
	FILE* f;
	char *line = NULL, *cp;
	size_t linesize = 0, key_end;
	u_int lineno = 0;
	struct logindefs_entry** vec = NULL;
	size_t vec_cap = 0, vec_len = 0;

	f = fopen(filename, "r");
	if (!f)
		return NULL;

	while (getline(&line, &linesize, f) != -1) {
		if (++lineno > 1000)
			fatal("Too many lines in logindefs file %s", filename);

		cp = line + strspn(line, " \t");
		if (!*cp || *cp == '#' || *cp == '\n')
			continue;

		cp[strcspn(cp, "\n")] = '\0';

		key_end = strcspn(cp, " \t");
		if (cp[key_end] == '\0' || key_end == 0) {
			fprintf(stderr, "Bad line %u in %.100s\n", lineno, filename);
			continue;
		}

		struct logindefs_entry *entry = xmalloc(sizeof(struct logindefs_entry));

		cp[key_end] = '\0';
		entry->key = strdup(cp);
		cp += key_end + 1;
		cp += strspn(cp, " \t");
		entry->value = strdup(cp);

		/* always reserve one more for the terminating null pointer */
		if (vec_len + 2 > vec_cap) {
			if (vec_cap == 0)
				vec_cap = 4;
			else
				vec_cap *= 2;
			vec = xreallocarray(vec, vec_cap, sizeof(struct logindefs_entry*));
		}
		vec[vec_len++] = entry;
	}
	free(line);

	if (vec)
		vec[vec_len + 1] = NULL;

	fclose(f);
	return vec;
}

static void free_logindefs_entries(struct logindefs_entry** entries) {
	struct logindefs_entry** e;
	for (e = entries; *e; e++) {
		free((*e)->key);
		free((*e)->value);
		free(*e);
	}
	free(entries);
}

#endif

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

int
pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, size_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	char *name;
	int i;

	i = openpty(ptyfd, ttyfd, NULL, NULL, NULL);
	if (i == -1) {
		error("openpty: %.100s", strerror(errno));
		return 0;
	}
	name = ttyname(*ttyfd);
	if (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	return 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

void
pty_release(const char *tty)
{
#if !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	if (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	if (chmod(tty, (mode_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#endif /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

void
pty_make_controlling_tty(int *ttyfd, const char *tty)
{
	int fd;

	/* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	if (fd >= 0) {
		(void) ioctl(fd, TIOCNOTTY, NULL);
		close(fd);
	}
#endif /* TIOCNOTTY */
	if (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	if (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#ifdef TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	if (ioctl(*ttyfd, TIOCSCTTY, NULL) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#endif /* TIOCSCTTY */
#ifdef NEED_SETPGRP
	if (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#endif /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	if (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	else
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	if (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	else
		close(fd);
}

/* Changes the window size associated with the pty. */

void
pty_change_window_size(int ptyfd, u_int row, u_int col,
	u_int xpixel, u_int ypixel)
{
	struct winsize w;

	/* may truncate u_int -> u_short */
	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(void) ioctl(ptyfd, TIOCSWINSZ, &w);
}

void
pty_setowner(struct passwd *pw, const char *tty)
{
	struct group *grp = NULL;
	gid_t gid;
	mode_t mode = 0;
	struct stat st;

#ifdef HAVE_ETC_LOGIN_DEFS
	struct logindefs_entry **logindefs, **defp;
	char *endptr;
	u_long l;

	logindefs = read_logindefs_file("/etc/login.defs");
	if (logindefs) {
		for (defp = logindefs; *defp; defp++) {
			if (0 == strcmp((*defp)->key, "TTYGROUP")) {
				grp = getgrnam((*defp)->value);
				if (grp == NULL)
					debug("%s: Group %.100s defined in /etc/login.defs "
							"not found", __func__, (*defp)->value);
			} else if (0 == strcmp((*defp)->key, "TTYPERM")) {
				l = strtoul((*defp)->value, &endptr, 0);
				if (*endptr) {
					debug("%s: Could not parse \"%.100s\" from /etc/login.defs "
							"to mode", __func__, (*defp)->value);
				} else if (l <= 0 || l >= 0777) {
					/* mode 0 is invalid, someone should be able to access the tty */
					debug("%s: Mode %#04o in /etc/login.defs is out of range",
							__func__, mode);
				} else
					mode = l;
			}
		}
		free_logindefs_entries(logindefs);
	}
#endif

	/* Determine the group to make the owner of the tty. */
	if (grp == NULL) {
		grp = getgrnam("tty");
		if (grp == NULL)
			debug("%s: no tty group", __func__);
	}
	gid = (grp != NULL) ? grp->gr_gid : pw->pw_gid;
	if (mode == 0)
		mode = (grp != NULL) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	if (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#ifdef WITH_SELINUX
	ssh_selinux_setup_pty(pw->pw_name, tty);
#endif

	if (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		if (chown(tty, pw->pw_uid, gid) == -1) {
			if (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			else
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	if ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		if (chmod(tty, mode) == -1) {
			if (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
			else
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
		}
	}
}

/* Disconnect from the controlling tty. */
void
disconnect_controlling_tty(void)
{
#ifdef TIOCNOTTY
	int fd;

	if ((fd = open(_PATH_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		(void) ioctl(fd, TIOCNOTTY, NULL);
		close(fd);
	}
#endif /* TIOCNOTTY */
}
