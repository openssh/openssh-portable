#ifndef _HAVE_LOGINREC_H_
#define _HAVE_LOGINREC_H_

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
 ** loginrec.h:  platform-independent login recording and lastlog retrieval
 **/

#include "includes.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* RCSID("$Id: loginrec.h,v 1.1 2000/06/03 14:57:40 andre Exp $"); */

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/* check if we have IP6 on this system */
#if defined(AF_INET6) || defined(INET6_ADDRSTRLEN)
#  define LOGIN_HAVE_IP6
#endif

/*
 * login_netinfo structure
 */

struct login_netinfo {
	struct sockaddr_in sa_in4;
#ifdef LOGIN_HAVE_IP6
	struct sockaddr_in6 sa_in6;
#endif

}; /* struct login_netinfo */


/*
 *   * logininfo structure  *
 */

/* types - different to utmp.h 'type' macros */
/* (though set to the same value as linux, openbsd and others...) */
#define LTYPE_LOGIN    7
#define LTYPE_LOGOUT   8

/* string lengths - set very long */
#define LINFO_PROGSIZE 64
#define LINFO_LINESIZE 64
#define LINFO_NAMESIZE 64
#define LINFO_HOSTSIZE 256

struct logininfo {

	char       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	int        progname_null;

	short int  type;                         /* type of login (LTYPE_*) */
  
	int        pid;                          /* PID of login process */
	int        uid;                          /* UID of this user */
	char       line[LINFO_LINESIZE];         /* tty/pty name */
	char       username[LINFO_NAMESIZE];     /* login username */
	char       hostname[LINFO_HOSTSIZE];     /* remote hostname */

	/* 'exit_status' structure components */
	int        exit;                        /* process exit status */
	int        termination;                 /* process termination status */
  
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	unsigned int tv_sec;
	unsigned int tv_usec;                   

	struct login_netinfo hostaddr;       /* caller's host address(es) */

}; /* struct logininfo */


/*
 * login recording functions
 */
/* construct a new login entry */
struct logininfo *login_alloc_entry(int pid,
				    const char *username,
				    const char *hostname, const char *line);
void login_free_entry(struct logininfo *li);
int login_init_entry(struct logininfo *li, 
			int pid, const char *username, 
			const char *hostname, const char *line);
void login_set_progname(struct logininfo *li,
			   const char *progname);
/* set the type field (skip if using ...login or ...logout) */
void login_set_type(struct logininfo *li, int type);
void login_set_pid(struct logininfo *li, int pid);
void login_set_uid(struct logininfo *li, int uid);
void login_set_line(struct logininfo *li, const char *line);
void login_set_username(struct logininfo *li, const char *username);
void login_set_hostname(struct logininfo *li, const char *hostname);
/* set the exit status (used by [uw]tmpx) */
void login_set_exitstatus(struct logininfo *li, int exit, int termination);
void login_set_time(struct logininfo *li, unsigned int tv_sec,
		    unsigned int tv_usec);
void login_set_current_time(struct logininfo *li);
/* set the network address based on network address type */
void login_set_ip4(struct logininfo *li,
		      const struct sockaddr_in *sa_in4);
# ifdef LOGIN_HAVE_IP6
void login_set_ip6(struct logininfo *li,
		      const struct sockaddr_in6 *sa_in6);
# endif /* LOGIN_HAVE_IP6 */
/* record the entry */
int login_write (struct logininfo *li);
int login_login (struct logininfo *li);
int login_logout(struct logininfo *li);
int login_log_entry(struct logininfo *li);

/*
 * login record retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
struct logininfo *login_getlastentry_name(struct logininfo *li,
					     const char *username);
struct logininfo *login_getlastentry_uid(struct logininfo *li,
					    const int pid);
/* lastlog *time* functions return time_t equivalent (uint) */
unsigned int login_getlasttime_name(const char *username);
unsigned int login_getlasttime_uid(const int pid);

/* produce various forms of the line filename */
char *line_fullname(char *dst, const char *src, int dstsize);
char *line_stripname(char *dst, const char *src, int dstsize);
char *line_abbrevname(char *dst, const char *src, int dstsize);


#endif /* _HAVE_LOGINREC_H_ */

