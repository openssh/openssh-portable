/*
 * Copyright (c) 2000 Andre Lucas.  All rights reserved.
 * Portions copyright (c) 1998 Todd C. Miller
 * Portions copyright (c) 1996 Jason Downs
 * Portions copyright (c) 1996 Theo de Raadt
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

/*
  The new login code explained
  ============================

  This code attempts to provide a common interface to login recording
  (utmp and friends) and last login time retrieval.

  Its primary means of achieving this is to use 'struct logininfo', a
  union of all the useful fields in the various different types of
  system login record structures one finds on UNIX variants.

  We depend on autoconf to define which recording methods are to be
  used, and which fields are contained in the relevant data structures
  on the local system. Many C preprocessor symbols affect which code
  gets compiled here.

  The code is designed to make it easy to modify a particular
  recording method, without affecting other methods nor requiring so
  many nested conditional compilation blocks as were commonplace in
  the old code.

  For login recording, we try to use the local system's libraries as
  these are clearly most likely to work correctly. For utmp systems
  this usually means login() and logout() or setutent() etc., probably
  in libutil, along with logwtmp() etc. On these systems, we fall back
  to writing the files directly if we have to, though this method
  requires very thorough testing so we do not corrupt local auditing
  information. These files and their access methods are very system
  specific indeed.
  
  For utmpx systems, the corresponding library functions are
  setutxent() etc. To the author's knowledge, all utmpx systems have
  these library functions and so no direct write is attempted. If such
  a system exists and needs support, direct analogues of the [uw]tmp
  code should suffice.

  Retrieving the time of last login ('lastlog') is in some ways even
  more problemmatic than login recording. Some systems provide a
  simple table of all users which we seek based on uid and retrieve a
  relatively standard structure. Others record the same information in
  a directory with a separate file, and others don't record the
  information separately at all. For systems in the latter category,
  we look backwards in the wtmp or wtmpx file for the last login entry
  for our user. Naturally this is slower and on busy systems could
  incur a significant performance penalty.

  Calling the new code
  --------------------
  
  In OpenSSH all login recording and retrieval is performed in
  login.c. Here you'll find working examples. Also, in the logintest.c
  program there are more examples.

  Internal handler calling method
  -------------------------------
  
  When a call is made to login_login() or login_logout(), both
  routines set a struct logininfo flag defining which action (log in,
  or log out) is to be taken. They both then call login_write(), which
  calls whichever of the many structure-specific handlers autoconf
  selects for the local system.

  The handlers themselves handle system data structure specifics. Both
  struct utmp and struct utmpx have utility functions (see
  construct_utmp*()) to try to make it simpler to add extra systems
  that introduce new features to either structure.

  While it may seem terribly wasteful to replicate so much similar
  code for each method, experience has shown that maintaining code to
  write both struct utmp and utmpx in one function, whilst maintaining
  support for all systems whether they have library support or not, is
  a difficult and time-consuming task.

  Lastlog support proceeds similarly. Functions login_get_lastlog()
  (and its OpenSSH-tuned friend login_get_lastlog_time()) call
  getlast_entry(), which tries one of three methods to find the last
  login time. It uses local system lastlog support if it can,
  otherwise it tries wtmp or wtmpx before giving up and returning 0,
  meaning "tilt".

  Maintenance
  -----------

  In many cases it's possible to tweak autoconf to select the correct
  methods for a particular platform, either by improving the detection
  code (best), or by presetting DISABLE_<method> or CONF_<method>_FILE
  symbols for the platform.

  Use logintest to check which symbols are defined before modifying
  configure.in and loginrec.c. (You have to build logintest yourself
  with 'make logintest' as it's not built by default.)

  Otherwise, patches to the specific method(s) are very helpful!
  
*/

/**
 ** TODO:
 **   homegrown ttyslot()q
 **   test, test, test
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

#if HAVE_UTMP_H
# include <utmp.h>
#endif
#if HAVE_UTMPX_H
# include <utmpx.h>
#endif
#if HAVE_LASTLOG_H
# include <lastlog.h>
#endif

#include "ssh.h"
#include "xmalloc.h"
#include "loginrec.h"

RCSID("$Id: loginrec.c,v 1.4 2000/06/07 11:32:13 djm Exp $");

/**
 ** prototypes for helper functions in this file
 **/

#if HAVE_UTMP_H
void set_utmp_time(struct logininfo *li, struct utmp *ut);
void construct_utmp(struct logininfo *li, struct utmp *ut);
#endif

#ifdef HAVE_UTMPX_H
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

/* Record a login */
int
login_login (struct logininfo *li)
{
	li->type = LTYPE_LOGIN;
	return login_write(li);
}


/* Record a logout */
int
login_logout(struct logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	return login_write(li);
}


/* Retrieve the last login time for a user (or fake on from wtmp/wtmpx) */
unsigned int
login_get_lastlog_time(const int uid)
{
	struct logininfo li;

	login_get_lastlog(&li, uid);
	return li.tv_sec;
}

/* Retrieve a lastlog entry (or fake one from wtmp/wtmpx) */
struct logininfo *
login_get_lastlog(struct logininfo *li, const int uid)
{
	memset(li, '\0', sizeof(struct logininfo));
	li->uid = uid;
	if (getlast_entry(li))
		return li;
	else
		return 0;
}


/* login_alloc_entry()    - allocate and initialise a logininfo */
struct
logininfo *login_alloc_entry(int pid, const char *username,
			     const char *hostname, const char *line)
{
	struct logininfo *newli;

	newli = (struct logininfo *) xmalloc (sizeof(struct logininfo));
	(void)login_init_entry(newli, pid, username, hostname, line);
	return newli;
}


/* login_free_entry()    - free struct memory (trivial) */
void
login_free_entry(struct logininfo *li)
{
	xfree(li);
}


/* login_init_entry()   - initialise a struct logininfo */
int
login_init_entry(struct logininfo *li, int pid, const char *username, 
		 const char *hostname, const char *line)
{
	/* zero the structure */
	memset(li, 0, sizeof(struct logininfo));
  
	li->pid = pid;
	/* set the line information */
	if (line)
		line_fullname(li->line, line, sizeof(li->line));

	if (username)
		strlcpy(li->username, username, sizeof(li->username));
	if (hostname)
		strlcpy(li->hostname, hostname, sizeof(li->hostname));
	return 1;
}


void
login_set_current_time(struct logininfo *li)
{
#ifdef HAVE_SYS_TIME_H
	struct timeval tv;

	gettimeofday(&tv, NULL);
	li->tv_sec = tv.tv_sec ; li->tv_usec = tv.tv_usec;
#else
	time_t tm = time(0);

	li->tv_sec = tm; li->tv_usec = 0;
#endif
}


/* copy a sockaddr_* into our logininfo */
void
login_set_addr(struct logininfo *li, const struct sockaddr *sa,
	       const unsigned int sa_size)
{
	unsigned int bufsize = sa_size;

	/* make sure we don't overrun our union */
	if (sizeof(li->hostaddr) < sa_size)
		bufsize = sizeof(li->hostaddr);

	memcpy((void *)&(li->hostaddr.sa), (const void *)sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/

int
login_write (struct logininfo *li)
{
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


/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
int
getlast_entry(struct logininfo *li)
{
#ifdef USE_LASTLOG
	if (lastlog_get_entry(li))
		return 1;
	else
		return 0;
#else
	/* !USE_LASTLOG */

	/* Try to retrieve the last login time from wtmp */
#  if defined(USE_WTMP) && (defined(HAVE_TIME_IN_UTMP) || defined(HAVE_TV_IN_UTMP))
	/* retrieve last login time from utmp */
	if (wtmp_get_entry(li))
		return 1;
	else
		return 0;
#  else

	/* If wtmp isn't available, try wtmpx */

#    if defined(USE_WTMPX) && (defined(HAVE_TIME_IN_UTMPX) || defined(HAVE_TV_IN_UTMPX))
	/* retrieve last login time from utmpx */
	if (wtmpx_get_entry(li))
		return 1;
	else
		return 0;
#    else

	/* Give up: No means of retrieving last login time */
	return 0;
#    endif
#  endif
#endif
/* USE_LASTLOG */
}



/*
 * 'line' string utility functions
 *
 * These functions process the 'line' string into one of three forms:
 *
 * 1. The full filename (including '/dev')
 * 2. The stripped name (excluding '/dev')
 * 3. The abbreviated name (e.g. /dev/ttyp00 -> yp00
 *                               /dev/pts/1  -> ts/1 )
 *
 * Form 3 is used on some systems to identify a .tmp.? entry when
 * attempting to remove it. Typically both addition and removal is
 * performed by one application - say, sshd - so as long as the choice
 * uniquely identifies a terminal it's ok.
 */


/* line_fullname(): add the leading '/dev/' if it doesn't exist make
 * sure dst has enough space, if not just copy src (ugh) */
char *
line_fullname(char *dst, const char *src, int dstsize)
{
	memset(dst, '\0', dstsize);
	if ((strncmp(src, "/dev/", 5) == 0) || (dstsize < (strlen(src) + 5)))
		strlcpy(dst, src, dstsize);
	else {
		strlcpy(dst, "/dev/", 5);
		strlcat(dst, src, dstsize);
	}
	return dst;
}


/* line_stripname(): strip the leading '/dev' if it exists, return dst */
char *
line_stripname(char *dst, const char *src, int dstsize)
{
	memset(dst, '\0', dstsize);
	if (strncmp(src, "/dev/", 5) == 0)
		strlcpy(dst, &src[5], dstsize);
	else
		strlcpy(dst, src, dstsize);
	return dst;
}

  
/* line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination */
char *
line_abbrevname(char *dst, const char *src, int dstsize) {
	memset(dst, '\0', dstsize);
	src += (strlen(src) - dstsize);
	strncpy(dst, src, dstsize); /* note: _don't_ change this to strlcpy */
	return dst;
}


/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#if defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
void
set_utmp_time(struct logininfo *li, struct utmp *ut)
{
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
		    struct utmp *ut)
{
	memset(ut, '\0', sizeof(struct utmp));
#ifdef HAVE_ID_IN_UTMP
	line_abbrevname(ut->ut_id, li->line, sizeof(ut->ut_id));
#endif

#ifdef HAVE_TYPE_IN_UTMP
	/* This is done here to keep utmp constants out of login.h */
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
	/* this is just a 32-bit IP address */
	if (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
#endif 
}

#endif
/* USE_UTMP || USE_WTMP || USE_LOGIN */



/**
 ** utmpx utility functions
 **
 ** These functions manipulate struct utmpx, accounting for system
 ** variations.
 **/

#if defined(USE_UTMPX) || defined (USE_WTMPX)

/* build the utmpx structure */
void
set_utmpx_time(struct logininfo *li, struct utmpx *utx)
{
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
construct_utmpx(struct logininfo *li, struct utmpx *utx)
{
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
	/* FIXME: (ATL) not supported yet */
#endif
#ifdef HAVE_SYSLEN_IN_UTMPX  
	/* this is safe because of the extra nulls in logininfo */
	utx->ut_syslen = strlen(li->hostname);
#endif
}

#endif
/* USE_UTMPX || USE_WTMPX */



/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */

#ifdef USE_UTMP

/* if we can, use pututline() etc. */
#if !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
    defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
#endif


/* write a utmp entry with the system's help (pututline() and pals) */
#ifdef UTMP_USE_LIBRARY
static int
utmp_write_library(struct logininfo *li, struct utmp *ut)
{
	setutent();
	pututline(ut);

#ifdef HAVE_ENDUTENT
	endutent();
#endif
	return 1;
}

#else

/* write a utmp entry direct to the file */
/* This is a slightly modification of code in OpenBSD's login.c */
static int
utmp_write_direct(struct logininfo *li, struct utmp *ut)
{
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
}
#endif /* UTMP_USE_LIBRARY */


static int
utmp_perform_login(struct logininfo *li)
{
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
}


static int
utmp_perform_logout(struct logininfo *li)
{
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
}


int
utmp_write_entry(struct logininfo *li)
{
	switch(li->type) {
	case LTYPE_LOGIN:
		return utmp_perform_login(li);

	case LTYPE_LOGOUT:
		return utmp_perform_logout(li);

	default:
		log("utmp_write_entry: invalid type field");
		return 0;
	}
}


#endif
/* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#ifdef USE_UTMPX

/* if we have the wherewithall, use pututxline etc. */
#if !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) \
    && defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
#endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
#ifdef UTMPX_USE_LIBRARY
static int
utmpx_write_library(struct logininfo *li, struct utmpx *utx)
{
	setutxent();
	pututxline(utx);

#ifdef HAVE_ENDUTXENT
	endutxent();
#endif
	return 1;
}

#else
/* UTMPX_USE_LIBRARY */


/* write a utmp entry direct to the file */
static int
utmpx_write_direct(struct logininfo *li, struct utmpx *utx)
{  
	log("utmpx_write_direct: not implemented!");
	return 0;
}

#endif
/* UTMPX_USE_LIBRARY */

static int
utmpx_perform_login(struct logininfo *li)
{
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
}


static int
utmpx_perform_logout(struct logininfo *li)
{
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
}


int
utmpx_write_entry(struct logininfo *li)
{
	switch(li->type) {
	case LTYPE_LOGIN:
		return utmpx_perform_login(li);
	case LTYPE_LOGOUT:
		return utmpx_perform_logout(li);
	default:
		log("utmpx_write_entry: invalid type field");
		return 0;
	}
}


#endif
/* USE_UTMPX */


/**
 ** Low-level wtmp functions
 **/

#ifdef USE_WTMP 

/* write a wtmp entry direct to the end of the file */
/* This is a slight modification of code in OpenBSD's logwtmp.c */
static int
wtmp_write(struct logininfo *li, struct utmp *ut)
{
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
}


static int
wtmp_perform_login(struct logininfo *li){
	struct utmp ut;

	construct_utmp(li, &ut);
	return wtmp_write(li, &ut);
}


static int
wtmp_perform_logout(struct logininfo *li)
{
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
}


int
wtmp_write_entry(struct logininfo *li)
{
	switch(li->type) {
	case LTYPE_LOGIN:
		return wtmp_perform_login(li);
	case LTYPE_LOGOUT:
		return wtmp_perform_logout(li);
	default:
		log("wtmp_write_entry: invalid type field");
		return 0;
	}
}


int
wtmp_get_entry(struct logininfo *li)
{
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
}


#endif
/* USE_WTMP */


/**
 ** Low-level wtmpx functions
 **/

#ifdef USE_WTMPX

/* write a wtmpx entry direct to the end of the file */
/* This is a slight modification of code in OpenBSD's logwtmp.c */
static int
wtmpx_write(struct logininfo *li, struct utmpx *utx)
{
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
}


static int
wtmpx_perform_login(struct logininfo *li)
{
	struct utmpx utx;

	construct_utmpx(li, &utx);
	return wtmpx_write(li, &utx);
}


static int
wtmpx_perform_logout(struct logininfo *li)
{
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

}


int
wtmpx_write_entry(struct logininfo *li)
{
	switch(li->type) {
	case LTYPE_LOGIN:
		return wtmpx_perform_login(li);
	case LTYPE_LOGOUT:
		return wtmpx_perform_logout(li);
	default:
		log("wtmpx_write_entry: invalid type field");
		return 0;
	}
}


int
wtmpx_get_entry(struct logininfo *li)
{
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
}


#endif /* USE_WTMPX */


/**
 ** Low-level libutil login() functions
 **/

#ifdef USE_LOGIN

static int
syslogin_perform_login(struct logininfo *li)
{
	struct utmp *ut;

	if (! (ut = (struct utmp *)malloc(sizeof(struct utmp)))) {
		log("syslogin_perform_login: couldn't malloc()");
		return 0;
	}
	construct_utmp(li, ut);
	login(ut);

	return 1;
}


static int
syslogin_perform_logout(struct logininfo *li)
{
#ifdef HAVE_LOGOUT
	char line[8];
  
	(void)line_stripname(line, li->line, sizeof(line));

	if (!logout(line)) {
		log("syslogin_perform_logout: logout() returned an error");
# ifdef HAVE_LOGWTMP
	} else {
		logwtmp(line, "", "");
	}
# endif
	/* TODO: what to do if we have login, but no logout?
	 * what if logout but no logwtmp? All routines are in libutil
	 * so they should all be there, but... */
#endif
	return 1;
}


int
syslogin_write_entry(struct logininfo *li)
{
	switch (li->type) {
	case LTYPE_LOGIN:
		return syslogin_perform_login(li);
	case LTYPE_LOGOUT:
		return syslogin_perform_logout(li);
	default:
		log("syslogin_write_entry: Invalid type field");
		return 0;
	}
}


#endif /* USE_LOGIN */

/* end of file log-syslogin.c */


/**
 ** Low-level lastlog functions
 **/

#ifdef USE_LASTLOG

static void
lastlog_construct(struct logininfo *li, struct lastlog *last)
{
	/* clear the structure */
	memset(last, '\0', sizeof(struct lastlog));
  
	(void)line_stripname(last->ll_line, li->line,
			     sizeof(last->ll_line));
	strlcpy(last->ll_host, li->hostname, sizeof(last->ll_host));
	last->ll_time = li->tv_sec;
}


#define LL_FILE 1
#define LL_DIR 2
#define LL_OTHER 3

static int
lastlog_filetype(char *filename)
{
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
}


/* open the file (using filemode) and seek to the login entry */
static int
lastlog_openseek(struct logininfo *li, int *fd, int filemode)
{
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
}

static int
lastlog_perform_login(struct logininfo *li)
{
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
}


int
lastlog_write_entry(struct logininfo *li)
{
	switch(li->type) {
	case LTYPE_LOGIN:
		return lastlog_perform_login(li);
	default:
		log("lastlog_write_entry: Invalid type field");
		return 0;
	}
}


static void
lastlog_populate_entry(struct logininfo *li, struct lastlog *last)
{
	line_fullname(li->line, last->ll_line, sizeof(li->line));
	strlcpy(li->hostname, last->ll_host, sizeof(li->hostname));
	li->tv_sec = last->ll_time;
}


int
lastlog_get_entry(struct logininfo *li)
{
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
}


#endif /* USE_LASTLOG */
