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
RCSID("$OpenBSD: login.c,v 1.14 2000/06/20 01:39:42 markus Exp $");

#include "loginrec.h"

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host the user logged in from will be returned in buf.
 */

unsigned long
get_last_login_time(uid_t uid, const char *logname,
		    char *buf, unsigned int bufsize)
{
  struct logininfo li;

  login_get_lastlog(&li, uid);
  strlcpy(buf, li.hostname, bufsize);
  return li.tv_sec;
}

/*
 * Records that the user has logged in.  I these parts of operating systems
 * were more standardized.
 */

void
record_login(pid_t pid, const char *ttyname, const char *user, uid_t uid,
	     const char *host, struct sockaddr * addr)
{
  struct logininfo *li;

  li = login_alloc_entry(pid, user, host, ttyname);
  login_set_addr(li, addr, sizeof(struct sockaddr));
  login_login(li);
  login_free_entry(li);
}

/* Records that the user has logged out. */

void
record_logout(pid_t pid, const char *ttyname)
{
  struct logininfo *li;

  li = login_alloc_entry(pid, NULL, NULL, ttyname);
  login_logout(li);
  login_free_entry(li);
}
