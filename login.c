/*
 * 
 * login.c
 * 
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * 
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * 
 * Created: Fri Mar 24 14:51:08 1995 ylo
 * 
 * This file performs some of the things login(1) normally does.  We cannot
 * easily use something like login -p -h host -f user, because there are
 * several different logins around, and it is hard to determined what kind of
 * login the current system has.  Also, we want to be able to execute commands
 * on a tty.
 * 
 */

#include "includes.h"
RCSID("$Id: login.c,v 1.18 2000/01/14 04:45:50 damien Exp $");

#if defined(HAVE_UTMPX_H) && defined(USE_UTMPX)
# include <utmpx.h>
#endif
#ifdef HAVE_UTMP_H
# include <utmp.h>
#endif
#include "ssh.h"

#ifdef HAVE_UTIL_H
# include <util.h>
#endif
#ifdef HAVE_LASTLOG_H
# include <lastlog.h>
#endif
#ifdef HAVE_LOGIN_H
# include <login.h>
#endif

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host the user logged in from will be returned in buf.
 */

/*
 * Returns the time when the user last logged in (or 0 if no previous login
 * is found).  The name of the host used last time is returned in buf.
 */

unsigned long 
get_last_login_time(uid_t uid, const char *logname,
		    char *buf, unsigned int bufsize)
{
#if defined(_PATH_LASTLOG) && !defined(DISABLE_LASTLOG)
	struct lastlog ll;
	char *lastlog;
	int fd;
#ifdef LASTLOG_IS_DIR
	char buf[1024];
#endif /* LASTLOG_IS_DIR */

	lastlog = _PATH_LASTLOG;
	buf[0] = '\0';

#ifdef LASTLOG_IS_DIR
	fd = open(lastlog, O_RDONLY);
	if (fd < 0)
		return 0;
	lseek(fd, (off_t) ((long) uid * sizeof(ll)), SEEK_SET);
#else /* LASTLOG_IS_DIR */
	snprintf(buf, sizeof(buf), "%s/%s", lastlog, logname);
	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return 0;
#endif /* LASTLOG_IS_DIR */
	if (read(fd, &ll, sizeof(ll)) != sizeof(ll)) {
		close(fd);
		return 0;
	}
	close(fd);
	if (bufsize > sizeof(ll.ll_host) + 1)
		bufsize = sizeof(ll.ll_host) + 1;
	strncpy(buf, ll.ll_host, bufsize - 1);
	buf[bufsize - 1] = 0;
	return ll.ll_time;

#else /* defined(_PATH_LASTLOG) && !defined(DISABLE_LASTLOG) */
	/* Look in wtmp for the last login */
	struct utmp  wt;
	char        *wt_file = _PATH_WTMP;
	int         fd1;
	unsigned long t = 0;

	if ( (fd1 = open(wt_file, O_RDONLY)) < 0 ) {
		error("Couldn't open %.100s to find last login time.", wt_file);
		return 0;
	}

	/* seek to last record of file */
	lseek(fd1, (off_t)(0-sizeof(struct utmp)), SEEK_END);

	/* loop through wtmp for our last user login record */
	do {
		if (read(fd1, &wt, sizeof(wt)) != sizeof(wt)) {
			close(fd1);
			return 0;
		}

		if ( wt.ut_type == USER_PROCESS) {
			if ( !strncmp(logname, wt.ut_user, 8) ) {
				t = (unsigned long) wt.ut_time;
#ifdef HAVE_HOST_IN_UTMP
				if (bufsize > sizeof(wt.ut_host) + 1)
				bufsize = sizeof(wt.ut_host) + 1;
				strncpy(buf, wt.ut_host, bufsize - 1);
				buf[bufsize - 1] = 0;
#else /* HAVE_HOST_IN_UTMP */
				buf[0] = 0;
#endif /* HAVE_HOST_IN_UTMP */
			}
		}

		if (lseek(fd1, (off_t)(0-2*sizeof(struct utmp)), SEEK_CUR) == -1)
			break;
	} while (t == 0);

	return t;
#endif /* defined(_PATH_LASTLOG) && !defined(DISABLE_LASTLOG) */
}

/*
 * Records that the user has logged in.  I these parts of operating systems
 * were more standardized.
 */

void 
record_login(int pid, const char *ttyname, const char *user, uid_t uid,
	     const char *host, struct sockaddr * addr)
{
#if defined(_PATH_LASTLOG) && !defined(DISABLE_LASTLOG)
	struct lastlog ll;
	char *lastlog;
#ifdef LASTLOG_IS_DIR
	char buf[1024];
#endif /* LASTLOG_IS_DIR */
#endif /* defined(_PATH_LASTLOG) && !defined(DISABLE_LASTLOG) */
	struct utmp u;
#if defined(HAVE_UTMPX_H) && defined(USE_UTMPX)
	struct utmpx utx;
#endif

	/* Construct an utmp/wtmp entry. */
	memset(&u, 0, sizeof(u));
	strncpy(u.ut_line, ttyname + 5, sizeof(u.ut_line));
#if defined(HAVE_ID_IN_UTMP)
	strncpy(u.ut_id, ttyname + 8, sizeof(u.ut_id));
#endif /* defined(HAVE_ID_IN_UTMP) */ 
	strncpy(u.ut_name, user, sizeof(u.ut_name));
#if defined(HAVE_TV_IN_UTMP)
	(void)gettimeofday(&u.ut_tv, NULL);
#else /* defined(HAVE_TV_IN_UTMP) */
	u.ut_time = time(NULL);
#endif /* defined(HAVE_TV_IN_UTMP) */
#if defined(HAVE_PID_IN_UTMP)
	u.ut_pid = (pid_t)pid;
#endif /* HAVE_PID_IN_UTMP */
#if defined(HAVE_TYPE_IN_UTMP)
 	u.ut_type = (uid == -1)?DEAD_PROCESS:USER_PROCESS;
#endif /* HAVE_TYPE_IN_UTMP */
#if defined(HAVE_HOST_IN_UTMP)
	strncpy(u.ut_host, host, sizeof(u.ut_host));
#endif
#if defined(HAVE_ADDR_IN_UTMP)
	switch (addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *in = (struct sockaddr_in*)addr;
			memcpy(&(u.ut_addr), &(in->sin_addr), sizeof(&(in->sin_addr)));
			break;
		}
#if defined(HAVE_ADDR_V6_IN_UTMP)
		case AF_INET6: {
			struct sockaddr_in6 *in6 = (struct sockaddr_in6*)addr;
			memcpy(u.ut_addr_v6, &(in6->sin6_addr), sizeof(&(in6->sin6_addr)));
			break;
		}
#endif
		default:
			break;
	}
#endif

#if defined(HAVE_UTMPX_H) && defined(USE_UTMPX)
	memset(&utx, 0, sizeof(utx));
	strncpy(utx.ut_user, user, sizeof(utx.ut_name));
	strncpy(utx.ut_line, ttyname + 5, sizeof(utx.ut_line));
	strncpy(utx.ut_id, ttyname + 8, sizeof(utx.ut_id));
	utx.ut_pid = (pid_t)pid;
	(void)gettimeofday(&utx.ut_tv, NULL);
 	utx.ut_type = (uid == -1)?DEAD_PROCESS:USER_PROCESS;
# ifdef HAVE_HOST_IN_UTMPX
#  ifdef HAVE_SYSLEN_IN_UTMPX
	utx.ut_syslen = strlen(host);
	strncpy(utx.ut_host, host, utx.ut_syslen);
#  else
	strncpy(utx.ut_host, host, sizeof(utx.ut_host));
#  endif /* HAVE_SYSLEN_IN_UTMPX */
# endif
#if defined(HAVE_ADDR_IN_UTMPX)
	switch (addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *in = (struct sockaddr_in*)addr;
			memcpy(&(utx.ut_addr), &(in->sin_addr), sizeof(&(in->sin_addr)));
			break;
		}
#if defined(HAVE_ADDR_V6_IN_UTMPX)
		case AF_INET6: {
			struct sockaddr_in6 *in6 = (struct sockaddr_in6*)addr;
			memcpy(utx.ut_addr_v6, &(in6->sin6_addr), sizeof(&(in6->sin6_addr)));
			break;
		}
#endif
		default:
			break;
	}
#endif
#endif /* defined(HAVE_UTMPX_H) && defined(USE_UTMPX) */

/*#if defined(HAVE_UTMPX_H) && defined(USE_UTMPX) && !defined(HAVE_LOGIN)*/
#if defined(HAVE_UTMPX_H) && defined(USE_UTMPX)
	login(&u, &utx);
#else /* defined(HAVE_UTMPX_H) && defined(USE_UTMPX) */
	login(&u);
#endif /* defined(HAVE_UTMPX_H) && defined(USE_UTMPX) */

#if defined(_PATH_LASTLOG) && !defined(DISABLE_LASTLOG)
	lastlog = _PATH_LASTLOG;

	/* Update lastlog unless actually recording a logout. */
	if (strcmp(user, "") != 0) {
		int fd;
		/*
		 * It is safer to bzero the lastlog structure first because
		 * some systems might have some extra fields in it (e.g. SGI)
		 */
		memset(&ll, 0, sizeof(ll));

		/* Update lastlog. */
		ll.ll_time = time(NULL);
		strncpy(ll.ll_line, ttyname + 5, sizeof(ll.ll_line));
		strncpy(ll.ll_host, host, sizeof(ll.ll_host));
#ifdef LASTLOG_IS_DIR
		snprintf(buf, sizeof(buf), "%s/%s", lastlog, logname);
		fd = open(buf, O_RDWR);
		if (fd >= 0) {
#else /* LASTLOG_IS_DIR */
		fd = open(lastlog, O_RDWR);
		if (fd >= 0) {
			lseek(fd, (off_t) ((long) uid * sizeof(ll)), SEEK_SET);
#endif /* LASTLOG_IS_DIR */
			if (write(fd, &ll, sizeof(ll)) != sizeof(ll))
				log("Could not write %.100s: %.100s", lastlog, strerror(errno));
			close(fd);
		}
	}
#endif /* defined(_PATH_LASTLOG) && !defined(DISABLE_LASTLOG) */
}

/* Records that the user has logged out. */

void 
record_logout(int pid, const char *ttyname)
{
#ifdef HAVE_LIBUTIL_LOGIN
	const char *line = ttyname + 5;	/* /dev/ttyq8 -> ttyq8 */
	if (logout(line))
		logwtmp(line, "", "");
#else /* HAVE_LIBUTIL_LOGIN */
	record_login(pid, ttyname, "", -1, "", NULL);
#endif /* HAVE_LIBUTIL_LOGIN */
}
