/*
 * Copyright (c) 2000 Andre Lucas.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Markus Friedl.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** 
 ** loginrec.c:  platform-independent login recording and lastlog retrieval
 **/

/**
 ** TODO:
 **   sockaddr_* stuff isn't finished
 **
 ** Platform status:
 ** ----------------
 **
 ** Known good:
 **   Linux (Redhat 6.2, need more variants)
 **   HP-UX 10.20 (gcc only)
 **
 ** Testing required: Please send reports!
 **   Solaris
 **   IRIX
 **   NetBSD
 **   HP-UX 11
 **   AIX
 **
 ** Platforms with known problems:
 **   NeXT
 **
 **/

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#ifdef HAVE_PWD_H
# include <pwd.h>
#endif
#ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
#else
#  include <time.h>
#endif

#include "ssh.h"
#include "xmalloc.h"
#include "loginrec.h"

RCSID("$Id: loginrec.c,v 1.2 2000/06/03 16:18:19 andre Exp $");


/**
 ** prototypes for helper functions in this file
 **/

#if HAVE_UTMP_H
# include <utmp.h>
void set_utmp_time(struct logininfo *li, struct utmp *ut);
void construct_utmp(struct logininfo *li, struct utmp *ut);
#endif

#ifdef HAVE_UTMPX_H
# include <utmpx.h>
void set_utmpx_time(struct logininfo *li, struct utmpx *ut);
void construct_utmpx(struct logininfo *li, struct utmpx *ut);
#endif

int utmp_write_entry(struct logininfo *li);
int utmpx_write_entry(struct logininfo *li);
int wtmp_write_entry(struct logininfo *li);
int wtmpx_write_entry(struct logininfo *li);
int lastlog_write_entry(struct logininfo *li);
int syslogin_write_entry(struct logininfo *li);

int getlast_entry(struct logininfo *li);
int lastlog_get_entry(struct logininfo *li);
int wtmp_get_entry(struct logininfo *li);
int wtmpx_get_entry(struct logininfo *li);


/**
 ** platform-independent login functions
 **/

/* login_alloc_entry()    - allocate and initialise a logininfo */
struct logininfo *login_alloc_entry(int pid, const char *username,
				       const char *hostname,
				       const char *line) {
	struct logininfo *newli;

	newli = (struct logininfo *) xmalloc (sizeof(struct logininfo));

	if (login_init_entry(newli, pid, username, hostname, line))
		return newli;
	else
		return 0;     /* fail */
} /* login_alloc_entry() */


/* login_free_entry()    - free struct memory (duh) */
void login_free_entry(struct logininfo *li) {
	if (li && (li->line[0] != '\0'))
		free ((void *)li);
	else
	  log("login_free_entry: attempt to free invalid entry (warning)");
} /* login_free_entry() */

/* login_init_entry()   - initialise a struct logininfo */
int login_init_entry(struct logininfo *li,
			int pid, const char *username, 
			const char *hostname, const char *line) {

	/* zero the structure */
	memset(li, 0, sizeof(struct logininfo));
  
	/* progname should be set outside this call */
	/* type stays null by default */
	login_set_pid(li, pid);
	/* set the line information */
	login_set_line(li, line);
	login_set_username(li, username);
	login_set_hostname(li, hostname);
	/* exit status and termination stay null by default */
	login_set_current_time(li);
	/* sockaddr_* stuff must be set separately (for now) */
	return 1;
} /* login_init_entry() */


void
login_set_progname(struct logininfo *li, const char *progname) {
	memset(li->progname, '\0', sizeof(li->progname));
	if (progname)
		strlcpy(li->progname, progname, sizeof(li->progname));
	else
		li->progname[0] = '\0';   /* set to null */
}

void
login_set_type(struct logininfo *li, int type) {
	li->type = type;
}

void
login_set_pid(struct logininfo *li, int pid) {
	if (!pid)
		li->pid = (int)getpid();
	else
		li->pid = pid;
}

void
login_set_uid(struct logininfo *li, int uid) {
	struct passwd *pw;

	li->uid = uid;
	/* now update the username */
	pw = getpwuid(uid);
	strlcpy(li->username, pw->pw_name, sizeof(li->username));
}

void
login_set_line(struct logininfo *li, const char *line) {
	if (line) {
		/* canonical form is the full name, i.e. including '/dev' */
		line_fullname(li->line, line, sizeof(li->line));
	} else
		li->line[0] = '\0';
}

void
login_set_username(struct logininfo *li, const char *username) {
	struct passwd *pw;

	if (!username) {
		li->username[0] = '\0';
		li->uid = -1;  /* hmm... */
	} else {
		strlcpy(li->username, username, sizeof(li->username));
		/* now update the uid */
		pw = getpwnam(username);
		li->uid = pw->pw_uid;
	}
}


void
login_set_hostname(struct logininfo *li, const char *hostname) {
	if (hostname) { /* can be null */
		strlcpy(li->hostname, hostname, sizeof(li->hostname));
	} 
}


void
login_set_exitstatus(struct logininfo *li,
			  int exit, int termination) {
	/* FIXME: (ATL) And? */
}


/* tv_usec should be null on systems without struct timeval */
void
login_set_time(struct logininfo *li,
		    unsigned int tv_sec, unsigned int tv_usec) {
	li->tv_sec = tv_sec;
	li->tv_usec = tv_usec;
}


void
login_set_current_time(struct logininfo *li) {
#ifdef HAVE_SYS_TIME_H
	struct timeval tv;

	gettimeofday(&tv, NULL);
	li->tv_sec = tv.tv_sec ; li->tv_usec = tv.tv_usec;
#else
	time_t t = time(0);
  
	li->tv_sec = t; li->tv_usec = 0;
#endif
}

void
login_set_ip4(struct logininfo *li,
		      const struct sockaddr_in *sa_in4) {
	memcpy((void *)&(li->hostaddr.sa_in4), (const void *)sa_in4,
	       sizeof(struct sockaddr_in));
}

#ifdef HAVE_IP6
void
login_set_ip6(struct logininfo *li,
		      const struct sockaddr_in6 *sa_in6) {
	memcpy((void *)&(li->hostaddr.sa_in4), (const void *)sa_in6,
	       sizeof(struct sockaddr_in6));
}
#endif

/*
 * record the entry
 */

int
login_write (struct logininfo *li) {
  
	if ((int)geteuid() != 0) {
	  log("Attempt to write login records by non-root user (aborting)");
	  return 1;
	}
	/* set the timestamp */
	login_set_current_time(li);
#ifdef USE_LOGIN
	syslogin_write_entry(li);
#endif
#ifdef USE_LASTLOG
	if (li->type == LTYPE_LOGIN) {
		lastlog_write_entry(li);
	}
#endif
#ifdef USE_UTMP
	utmp_write_entry(li);
#endif
#ifdef USE_WTMP
	wtmp_write_entry(li);
#endif
#ifdef USE_UTMPX
	utmpx_write_entry(li);
#endif
#ifdef USE_WTMPX
	wtmpx_write_entry(li);
#endif
	return 0;
}

int
login_login (struct logininfo *li) {
	li->type = LTYPE_LOGIN;
	return login_write(li);
}

int
login_logout(struct logininfo *li) {
	li->type = LTYPE_LOGOUT;
	return login_write(li);
}

int
login_log_entry(struct logininfo *li) {
	return login_write(li);
}


unsigned int
login_getlasttime_name(const char *username) {
	struct logininfo li;

	memset(&li, '\0', sizeof(li));
	login_set_username(&li, username);
	if (getlast_entry(&li))
		return li.tv_sec;
	else
		return 0;
} /* login_getlasttime_name() */


unsigned int
login_getlasttime_uid(const int uid) {
	struct logininfo li;

	memset(&li, '\0', sizeof(li));
	login_set_uid(&li, uid);
	if (getlast_entry(&li))
		return li.tv_sec;
	else
		return 0;
} /* login_getlasttime_uid() */


struct logininfo *
login_getlastentry_name(struct logininfo *li,
					  const char *username) {
	login_set_username(li, username);
	if (getlast_entry(li))
		return li;
	else
		return 0;
} /* login_getlastentry_name() */

struct logininfo *
login_getlastentry_uid(struct logininfo *li,
		       const int uid) {
	login_set_uid(li, uid);
	if (getlast_entry(li))
		return li;
	else
		return 0;
} /* login_getlastentry_uid() */


/**
 ** 'line' string utility functions
 **/

/*
 * process the 'line' string into three forms:
 * 1. The full filename (including '/dev')
 * 2. The stripped name (excluding '/dev')
 * 3. The abbreviated name (e.g. /dev/ttyp00
 *
 * Form 3 is used on some systems to identify a .tmp.? entry when
 * attempting to remove it. Typically both addition and removal is
 * performed by one application - say, sshd - so as long as the
 * choice uniquely identifies a terminal and is the same at login and
 * logout time, we're in good shape.
 *
 * NOTE: None of these calls actually allocate any memory -
 *       since their target is probably a structure, they don't
 *       need to.
 */


/* add the leading '/dev/' if it doesn't exist
 * make sure dst has enough space, if not just copy src (ugh) */
char *
line_fullname(char *dst, const char *src, int dstsize) {
	memset(dst, '\0', dstsize);
	if ((strncmp(src, "/dev/", 5) == 0) || (dstsize < (strlen(src) + 5)))
		strlcpy(dst, src, dstsize);
	else {
		strlcpy(dst, "/dev/", 5);
		strlcat(dst, src, dstsize);
	}
	return dst;
}

/* strip the leading '/dev' if it exists, return dst */
char *
line_stripname(char *dst, const char *src, int dstsize) {
	memset(dst, '\0', dstsize);
	if (strncmp(src, "/dev/", 5) == 0)
		strlcpy(dst, &src[5], dstsize);
	else
		strlcpy(dst, src, dstsize);
	return dst;
} /* stripdev() */
  
/* return the abbreviated (usually four-character) form *
 * simple algorithm for making name:
 * - first character is 'L' (arbitrary - 'lib(L)ogin' :-) )
 * - remaining n characters are last n characters of line
 * This is good for up to 999 ptys, I hope that's enough...
 */
char *
line_abbrevname(char *dst, const char *src, int dstsize) {
	memset(dst, '\0', dstsize);
	dst[0]='L';
	strlcpy(dst+1, &src[strlen(src)-(dstsize)], dstsize);
	return dst;
}


/**
 ** utmp utility functions
 **/

#if defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

#ifdef HAVE_UTMP_H
#  include <utmp.h>
#endif
#ifdef USE_TIMEVAL
#  include <sys/time.h>
#else
#  include <time.h>
#endif

/* build the utmp structure */
void
set_utmp_time(struct logininfo *li, struct utmp *ut) {
#ifdef HAVE_TV_IN_UTMP
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
#else
#  ifdef HAVE_TIME_IN_UTMP
	ut->ut_time = li->tv_sec;
#  endif
#endif
}

void
construct_utmp(struct logininfo *li,
		    struct utmp *ut) {
	memset(ut, '\0', sizeof(struct utmp));

#ifdef HAVE_ID_IN_UTMP
	line_abbrevname(ut->ut_id, li->line, sizeof(ut->ut_id));
#endif

#ifdef HAVE_TYPE_IN_UTMP
	/* this is done here to keep utmp constants out of login.h */
	switch (li->type) {
	case LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		break;
	case LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		break;
	}
#endif

#ifdef HAVE_PID_IN_UTMP
	ut->ut_pid = li->pid;
#endif
	line_stripname(ut->ut_line, li->line, sizeof(ut->ut_line));
	strlcpy(ut->ut_name, li->username, sizeof(ut->ut_name));
	set_utmp_time(li, ut);
#ifdef HAVE_HOST_IN_UTMP
	strlcpy(ut->ut_host, li->hostname, sizeof(ut->ut_host));
#endif
#ifdef HAVE_ADDR_IN_UTMP
	/* !!! not supported yet (can't see its big use either) */
#endif
  
} /* construct_utmp() */

#endif
/* USE_UTMP || USE_WTMP || USE_LOGIN */

/**
 ** utmpx utility functions
 **/

#if defined(USE_UTMPX) || defined (USE_WTMPX)

#ifdef HAVE_UTMPX_H
#  include <utmpx.h>
#endif
#ifdef USE_TIMEVAL
#  include <sys/time.h>
#else
#  include <time.h>
#endif

/* build the utmpx structure */
void
set_utmpx_time(struct logininfo *li, struct utmpx *utx) {
#ifdef HAVE_TV_IN_UTMPX
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
#else
#  ifdef HAVE_TIME_IN_UTMPX
	utx->ut_time = li->tv_sec;
#  endif
#endif
}

void
construct_utmpx(struct logininfo *li,
		     struct utmpx *utx) {
	memset(utx, '\0', sizeof(struct utmpx));

	line_abbrevname(utx->ut_id, li->line, sizeof(utx->ut_id));

	/* this is done here to keep utmp constants out of loginrec.h */
	switch (li->type) {
	case LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		break;
	case LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		break;
	}

	utx->ut_pid = li->pid;
	line_stripname(utx->ut_line, li->line, sizeof(utx->ut_line));
	strlcpy(utx->ut_name, li->username, sizeof(utx->ut_name));
	set_utmpx_time(li, utx);
#ifdef HAVE_HOST_IN_UTMPX
	strlcpy(utx->ut_host, li->hostname, sizeof(utx->ut_host));
#endif
#ifdef HAVE_ADDR_IN_UTMPX
	/* !!! not supported yet (some issues with types of addresses) */
#endif
#ifdef HAVE_SYSLEN_IN_UTMPX  
	/* this is safe because of the extra nulls in logininfo */
	utx->ut_syslen = strlen(li->hostname);
#endif
} /* construct_utmpx() */

#endif
/* USE_UTMPX || USE_WTMPX */



/**
 ** utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */

#ifdef USE_UTMP

#include <utmp.h>

/* if we can, use pututline() etc. */
#if !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
    defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
#endif


/* write a utmp entry with the system's help (pututline() and pals) */
#ifdef UTMP_USE_LIBRARY
static int
utmp_write_library(struct logininfo *li, struct utmp *ut) {

	setutent();
	pututline(ut);

#ifdef HAVE_ENDUTENT
	endutent();
#endif
	return 1;
} /* utmp_write_library() */

#else

/* write a utmp entry direct to the file */
/* This code is a slightly modification of code in OpenBSD's login.c
 *  (in libutil) and so is subject to the OpenBSD Licensing terms. */
static int
utmp_write_direct(struct logininfo *li, struct utmp *ut) {
	struct utmp old_ut;
	register int fd;
	int tty;

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

	if (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		(void)lseek(fd, (off_t)(tty * sizeof(struct utmp)), SEEK_SET);
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		if (   read(fd, &old_ut, sizeof(struct utmp)) == sizeof(struct utmp)
		       && ut->ut_host[0] == '\0'
		       && old_ut.ut_host[0] != '\0'
		       && strncmp(old_ut.ut_line, ut->ut_line, sizeof(ut->ut_line)) == 0
		       && strncmp(old_ut.ut_name, ut->ut_name, sizeof(ut->ut_name)) == 0  )
			(void)memcpy(ut->ut_host, old_ut.ut_host, sizeof(ut->ut_host));

		(void)lseek(fd, (off_t)(tty * sizeof(struct utmp)), SEEK_SET);
		if (write(fd, ut, sizeof(struct utmp))==-1)
			log("utmp_write_direct: error writing %s: %s",
				     UTMP_FILE, strerror(errno));
      
		(void)close(fd);
		return 1;
	} else
		return 0;
} /* utmp_write_direct() */

#endif /* UTMP_USE_LIBRARY */


static int
utmp_perform_login(struct logininfo *li) {
	struct utmp ut;

	construct_utmp(li, &ut);

#ifdef UTMP_USE_LIBRARY
	if (!utmp_write_library(li, &ut)) {
	  log("utmp_perform_login: utmp_write_library() failed");
		return 0;
	}
#else
	if (!utmp_write_direct(li, &ut)) {
		log("utmp_perform_login: utmp_write_direct() failed");
		return 0;
	}
#endif
	return 1;
} /* utmp_perform_login() */


static int
utmp_perform_logout(struct logininfo *li) {
	struct utmp ut;

	memset(&ut, '\0', sizeof(ut));
	set_utmp_time(li, &ut);
	line_stripname(ut.ut_line, li->line, sizeof(ut.ut_line));
#ifdef HAVE_ID_IN_UTMP
	line_abbrevname(ut.ut_id, li->line, sizeof(ut.ut_id));
#endif
#ifdef HAVE_TYPE_IN_UTMP
	ut.ut_type = DEAD_PROCESS;
#endif

#if   !defined(DISABLE_PUTUTLINE) \
    && defined(HAVE_SETUTENT) && defined(HAVE_PUTUTLINE)
	utmp_write_library(li, &ut);
#else
	utmp_write_direct(li, &ut);
#endif

	return 1;
} /* utmp_perform_logout() */


int
utmp_write_entry(struct logininfo *li) {

	switch(li->type) {
	case LTYPE_LOGIN:
		return utmp_perform_login(li);

	case LTYPE_LOGOUT:
		return utmp_perform_logout(li);

	default:
		log("utmp_write_entry: invalid type field");
		return 0;
	}
} /* utmp_write_entry() */


#endif
/* USE_UTMP */


/**
 ** utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#ifdef USE_UTMPX

#include <utmpx.h>

/* if we have the wherewithall, use pututxline etc. */
#if !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) \
    && defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
#endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
#ifdef UTMPX_USE_LIBRARY
static int
utmpx_write_library(struct logininfo *li, struct utmpx *utx) {

	setutxent();
	pututxline(utx);

#ifdef HAVE_ENDUTXENT
	endutxent();
#endif
	return 1;
} /* utmpx_write_library() */

#else
/* UTMPX_USE_LIBRARY */


/* write a utmp entry direct to the file */
static int
utmpx_write_direct(struct logininfo *li, struct utmpx *utx) {
  
	log("utmpx_write_direct: not implemented!");
	return 0;
 } /* utmpx_write_direct() */

#endif
/* UTMPX_USE_LIBRARY */

static int
utmpx_perform_login(struct logininfo *li) {
	struct utmpx utx;

	construct_utmpx(li, &utx);

#ifdef UTMPX_USE_LIBRARY
	if (!utmpx_write_library(li, &utx)) {
		log("utmpx_perform_login: utmp_write_library() failed");
		return 0;
	}
#else
	if (!utmpx_write_direct(li, &ut)) {
		log("utmpx_perform_login: utmp_write_direct() failed");
		return 0;
	}
#endif
	return 1;
} /* utmpx_perform_login() */


static int
utmpx_perform_logout(struct logininfo *li) {
	struct utmpx utx;

	memset(&utx, '\0', sizeof(utx));
	set_utmpx_time(li, &utx);
	line_stripname(utx.ut_line, li->line, sizeof(utx.ut_line));
#ifdef HAVE_ID_IN_UTMPX
	line_abbrevname(utx.ut_id, li->line, sizeof(utx.ut_id));
#endif
#ifdef HAVE_TYPE_IN_UTMPX
	utx.ut_type = DEAD_PROCESS;
#endif

#ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
#else
	utmpx_write_direct(li, &utx);
#endif

	return 1;
} /* utmpx_perform_logout() */


int
utmpx_write_entry(struct logininfo *li) {

	switch(li->type) {
	case LTYPE_LOGIN:
		return utmpx_perform_login(li);
	case LTYPE_LOGOUT:
		return utmpx_perform_logout(li);
	default:
		log("utmpx_write_entry: invalid type field");
		return 0;
	}
} /* utmpx_write_entry() */


#endif
/* USE_UTMPX */


/**
 ** wtmp functions
 **/

#ifdef USE_WTMP 

# include <utmp.h>

/* write a wtmp entry direct to the end of the file */
/* This code is a slight modification of code in OpenBSD's logwtmp.c
 * (in libutil) and so is subject to the OpenBSD licensing terms */
static int
wtmp_write(struct logininfo *li, struct utmp *ut) {
	struct stat buf;
	int fd, ret = 1;

	if ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		log("wtmp_write: problem writing %s: %s",
		    WTMP_FILE, strerror(errno));
		return 0;
	}
  
	if (fstat(fd, &buf) == 0) 
		if (write(fd, (char *)ut, sizeof(struct utmp)) != 
		    sizeof(struct utmp)) {
			ftruncate(fd, buf.st_size);
			log("wtmp_write: problem writing %s: %s",
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	(void)close(fd);

	return ret;
} /* wtmp_write() */



static int
wtmp_perform_login(struct logininfo *li) {
	struct utmp ut;

	construct_utmp(li, &ut);
	return wtmp_write(li, &ut);
} /* wtmp_perform_login() */


static int
wtmp_perform_logout(struct logininfo *li) {
	struct utmp ut;

	construct_utmp(li, &ut);
	/* blank out unnecessary fields */
	memset(&(ut.ut_name), '\0', sizeof(ut.ut_name));
#ifdef HAVE_ID_IN_UTMP
	memset(&(ut.ut_id), '\0', sizeof(ut.ut_id));
#endif
#ifdef HAVE_HOST_IN_UTMP
	memset(&(ut.ut_host), '\0', sizeof(ut.ut_host));
#endif
#ifdef HAVE_ADDR_IN_UTMP
	memset(&(ut.ut_addr), '\0', sizeof(ut.ut_addr));
#endif
	return wtmp_write(li, &ut);
} /* wtmp_perform_logout() */


int
wtmp_write_entry(struct logininfo *li) {

	switch(li->type) {
	case LTYPE_LOGIN:
		return wtmp_perform_login(li);
	case LTYPE_LOGOUT:
		return wtmp_perform_logout(li);
	default:
		log("wtmp_write_entry: invalid type field");
		return 0;
	}
} /* wtmp_write_entry() */



int
wtmp_get_entry(struct logininfo *li) {
	struct stat st;
	struct utmp ut;
	int fd;

	if ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		log("wtmp_get_entry: problem opening %s: %s",
		    WTMP_FILE, strerror(errno));
		return 0;
	}
  
	if (fstat(fd, &st) != 0) {
		log("wtmp_get_entry: couldn't stat %s: %s",
		    WTMP_FILE, strerror(errno));
		close(fd);
		return 0;
	}

	(void)lseek(fd, (off_t)(0-sizeof(struct utmp)), SEEK_END);

	do {
		if (read(fd, &ut, sizeof(ut)) != sizeof(ut)) {
			log("wtmp_get_entry: read of %s failed: %s",
			    WTMP_FILE, strerror(errno));
			close (fd);
			return 0;
		}

		/* Logouts are recorded as a blank username on a particular line.
		 * So, we just need to find the username in struct utmp */
		if ( strncmp(li->username, ut.ut_user, 8) == 0 ) {
			/* note we've already made sure there's a time in struct utmp */
#ifdef HAVE_TIME_IN_UTMP
			li->tv_sec = ut.ut_time;
#else
#  if HAVE_TV_IN_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
#endif
			line_fullname(li->line, ut.ut_line, sizeof(ut.ut_line));
#ifdef HAVE_HOST_IN_UTMP
			strlcpy(li->hostname, ut.ut_host, sizeof(ut.ut_host));
#endif
		}
		if (lseek(fd, (off_t)(0-2*sizeof(struct utmp)), SEEK_CUR) == -1) {
			close (fd);
			return 0;
		}
	} while (li->tv_sec == 0);
      
	return 1;
} /* wtmp_get_entry() */


#endif
/* USE_WTMP */


/**
 ** wtmpx functions
 **/

#ifdef USE_WTMPX

# include <utmpx.h>

/* write a wtmpx entry direct to the end of the file */
/* This code is a slight modification of code in OpenBSD's logwtmp.c
 * (in libutil) and so is subject to the OpenBSD licensing terms */
static int
wtmpx_write(struct logininfo *li, struct utmpx *utx) {
	struct stat buf;
	int fd, ret = 1;

	if ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		log("wtmpx_write: problem opening %s: %s",
		    WTMPX_FILE, strerror(errno));
		return 0;
	}

	if (fstat(fd, &buf) == 0) 
		if (write(fd, (char *)utx, sizeof(struct utmpx)) != 
		    sizeof(struct utmpx)) {
			ftruncate(fd, buf.st_size);
			log("wtmpx_write: problem writing %s: %s",
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	(void)close(fd);

	return ret;
} /* wtmpx_write() */



static int
wtmpx_perform_login(struct logininfo *li) {
	struct utmpx utx;

	construct_utmpx(li, &utx);
	return wtmpx_write(li, &utx);
} /* wtmpx_perform_login() */


static int
wtmpx_perform_logout(struct logininfo *li) {
	struct utmpx utx;

	construct_utmpx(li, &utx);
	/* blank out unnecessary fields */
	memset(&(utx.ut_name), '\0', sizeof(utx.ut_name));
#ifdef HAVE_ID_IN_UTMPX
	memset(&(utx.ut_id), '\0', sizeof(utx.ut_id));
#endif
#ifdef HAVE_HOST_IN_UTMPX
	memset(&(utx.ut_host), '\0', sizeof(utx.ut_host));
#endif
#ifdef HAVE_ADDR_IN_UTMPX
	memset(&(utx.ut_addr), '\0', sizeof(utx.ut_addr));
#endif
	return wtmpx_write(li, &utx);

} /* wtmpx_perform_logout() */


int
wtmpx_write_entry(struct logininfo *li) {

	switch(li->type) {
	case LTYPE_LOGIN:
		return wtmpx_perform_login(li);
	case LTYPE_LOGOUT:
		return wtmpx_perform_logout(li);
	default:
		log("wtmpx_write_entry: invalid type field");
		return 0;
	}
} /* wtmpx_write_entry() */



int
wtmpx_get_entry(struct logininfo *li) {
	struct stat st;
	struct utmpx utx;
	int fd;

	if ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		log("wtmpx_get_entry: problem opening %s: %s",
		    WTMPX_FILE, strerror(errno));
		return 0;
	}
  
	if (fstat(fd, &st) != 0) {
		log("wtmpx_get_entry: couldn't stat %s: %s",
		    WTMP_FILE, strerror(errno));
		close(fd);
		return 0;
	}

	(void)lseek(fd, (off_t)(0-sizeof(struct utmpx)), SEEK_END);

	do {
		if (read(fd, &utx, sizeof(utx)) != sizeof(utx)) {
			log("wtmpx_get_entry: read of %s failed: %s",
			    WTMPX_FILE, strerror(errno));
			close (fd);
			return 0;
		}

		/* Logouts are recorded as a blank username on a particular line.
		 * So, we just need to find the username in struct utmpx */
		if ( strncmp(li->username, utx.ut_user, 8) == 0 ) {
			/* note we've already made sure there's a time in struct utmp */
#ifdef HAVE_TV_IN_UTMPX
			li->tv_sec = utx.ut_tv.tv_sec;
#else
#  ifdef HAVE_TIME_IN_UTMPX
			li->tv_sec = utx.ut_time;
#  endif
#endif
			line_fullname(li->line, utx.ut_line, sizeof(utx.ut_line));
#ifdef HAVE_HOST_IN_UTMPX
			strlcpy(li->hostname, utx.ut_host, sizeof(utx.ut_line));
#endif
		}
		if (lseek(fd, (off_t)(0-2*sizeof(struct utmpx)), SEEK_CUR) == -1) {
			close (fd);
			return 0;
		}
	} while (li->tv_sec == 0);
	return 1;
} /* wtmpx_get_entry() */



#endif
/* USE_WTMPX */



/**
 ** libutil login() functions
 **/

#ifdef USE_LOGIN

#ifdef HAVE_UTMP_H
#  include <utmp.h>
#endif
#ifdef HAVE_UTIL_H
#  include <util.h>
#endif
#ifdef USE_TIMEVAL
#  include <sys/time.h>
#else
#  include <time.h>
#endif

static int
syslogin_perform_login(struct logininfo *li) {
	struct utmp *ut;

	if (! (ut = (struct utmp *)malloc(sizeof(struct utmp)))) {
		log("syslogin_perform_login: couldn't malloc()");
		return 0;
	}
	construct_utmp(li, ut);
	login(ut);

	return 1;
} /* syslogin_perform_login() */

static int
syslogin_perform_logout(struct logininfo *li) {

#ifdef HAVE_LOGOUT
	char line[8];
  
	(void)line_stripname(line, li->line, sizeof(line));

	if (!logout(line)) {
		log("syslogin_perform_logout: logout() returned an error");
#  ifdef HAVE_LOGWTMP
	} else {
		logwtmp(line, "", "");
	}
#  endif
	/* TODO: what to do if we have login, but no logout?
	 * what if logout but no logwtmp? All routines are in libutil
	 * so they should all be there, but... */
#endif
	return 1;
} /* syslogin_perform_logout() */



int
syslogin_write_entry(struct logininfo *li) {

	switch (li->type) {
	case LTYPE_LOGIN:
		return syslogin_perform_login(li);
	case LTYPE_LOGOUT:
		return syslogin_perform_logout(li);
	default:
		log("syslogin_write_entry: Invalid type field");
		return 0;
	}
} /* utmp_write_entry() */


#endif
/* USE_LOGIN */

/* end of file log-syslogin.c */


/**
 ** lastlog functions
 **/

#ifdef USE_LASTLOG

#ifdef HAVE_LASTLOG_H
# include <lastlog.h>
#else
# if !defined(USE_UTMP) && !defined(USE_WTMP)
#  include <utmp.h>
# endif
#endif


static void
lastlog_construct(struct logininfo *li,
			      struct lastlog *last) {
	/* clear the structure */
	memset(last, '\0', sizeof(struct lastlog));
  
	(void)line_stripname(last->ll_line, li->line,
			     sizeof(last->ll_line));
	strlcpy(last->ll_host, li->hostname, sizeof(last->ll_host));
	last->ll_time = li->tv_sec;
} /* lastlog_construct() */


#define LL_FILE 1
#define LL_DIR 2
#define LL_OTHER 3

static int
lastlog_filetype(char *filename) {
	struct stat st;

	if ( stat(LASTLOG_FILE, &st) != 0) {
		log("lastlog_perform_login: Couldn't stat %s: %s",
		    LASTLOG_FILE, strerror(errno));
		return 0;
	}

	if (S_ISDIR(st.st_mode))
		return LL_DIR;
	else if (S_ISREG(st.st_mode))
		return LL_FILE;
	else
		return LL_OTHER;
} /* lastlog_filetype() */


/* open the file (using filemode) and seek to the login entry */
static int
lastlog_openseek(struct logininfo *li, int *fd, int filemode) {

	off_t offset;
	int type;
	char lastlog_file[1024];

	type = lastlog_filetype(LASTLOG_FILE);
	switch (type) {
	case LL_FILE:
		strlcpy(lastlog_file, LASTLOG_FILE, sizeof(lastlog_file));
		break;
	case LL_DIR:
		snprintf(lastlog_file, sizeof(lastlog_file), "%s/%s",
			 LASTLOG_FILE, li->username);
		break;
	default:
		log("lastlog_openseek: %.100s is not a file or directory!",
		    LASTLOG_FILE);
		return 0;
	} /* switch */

	*fd = open(lastlog_file, filemode);
	if ( *fd < 0) {
		log("lastlog_openseek: Couldn't open %s: %s",
		    lastlog_file, strerror(errno));
		return 0;
	}

	/* find this uid's offset in the lastlog file */
	offset = (off_t) ( (long)li->uid * sizeof(struct lastlog));

	if ( lseek(*fd, offset, SEEK_SET) != offset ) {
		log("lastlog_openseek: %s->lseek(): %s",
		    lastlog_file, strerror(errno));
		return 0;
	}
	return 1;
} /* lastlog_openseek() */

static int
lastlog_perform_login(struct logininfo *li) {
	struct lastlog last;
	int fd;

	/* create our struct lastlog */
	lastlog_construct(li, &last);

	/* write the entry */
	if (lastlog_openseek(li, &fd, O_RDWR)) {
		if ( write(fd, &last, sizeof(struct lastlog)) 
		     != sizeof(struct lastlog) ) {
			log("lastlog_write_filemode: Error writing to %s: %s",
			    LASTLOG_FILE, strerror(errno));
			return 0;
		}
		return 1;
	} else
		return 0;
} /* lastlog_perform_login() */


int
lastlog_write_entry(struct logininfo *li) {

	switch(li->type) {
	case LTYPE_LOGIN:
		return lastlog_perform_login(li);
	default:
		log("lastlog_write_entry: Invalid type field");
		return 0;
	}
} /* lastlog_write_entry() */



static void
lastlog_populate_entry(struct logininfo *li,
				   struct lastlog *last) {
	line_fullname(li->line, last->ll_line, sizeof(li->line));
	strlcpy(li->hostname, last->ll_host, sizeof(li->hostname));
	li->tv_sec = last->ll_time;
} /* lastlog_populate_entry() */



int
lastlog_get_entry(struct logininfo *li) {
	struct lastlog last;
	int fd;

	if (lastlog_openseek(li, &fd, O_RDONLY)) {
		if ( read(fd, &last, sizeof(struct lastlog)) 
		     != sizeof(struct lastlog) ) {
			log("lastlog_write_filemode: Error reading from %s: %s",
			    LASTLOG_FILE, strerror(errno));
			return 0;
		} else {
			lastlog_populate_entry(li, &last);
			return 1;
		}

	} else
		return 0;    
} /* lastlog_get_entry() */


#endif
/* USE_LASTLOG */


/**
 ** lastlog retrieval functions
 **/

/* take the uid in li and return the last login time */
int
getlast_entry(struct logininfo *li) {

#ifdef USE_LASTLOG
	if (lastlog_get_entry(li))
		return 1;
	else
		return 0;
#else
	/* !USE_LASTLOG */
	/* Try to retrieve the last login time from another source */

#  if defined(USE_WTMP) && (defined(HAVE_TIME_IN_UTMP) || defined(HAVE_TV_IN_UTMP))

	/* retrieve last login time from utmp */
	if (wtmp_get_entry(li))
		return 1;
	else
		return 0;

#  else
#    if defined(USE_WTMPX) && (defined(HAVE_TIME_IN_UTMPX) || defined(HAVE_TV_IN_UTMPX))

	/* retrieve last login time from utmpx */
	if (wtmpx_get_entry(li))
		return 1;
	else
		return 0;

#    else

	/* no means of retrieving last login time */
	return 0;
#    endif
#  endif

#endif
	/* USE_LASTLOG */

}
