/*	$OpenBSD: log.h,v 1.3 2001/06/26 06:32:55 itojun Exp $	*/

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef SSH_LOG_H
#define SSH_LOG_H

#include <syslog.h> /* Needed for LOG_AUTHPRIV (if present) */

/* Supported syslog facilities and levels. */
typedef enum {
	SYSLOG_FACILITY_DAEMON,
	SYSLOG_FACILITY_USER,
	SYSLOG_FACILITY_AUTH,
#ifdef LOG_AUTHPRIV
	SYSLOG_FACILITY_AUTHPRIV,
#endif
	SYSLOG_FACILITY_LOCAL0,
	SYSLOG_FACILITY_LOCAL1,
	SYSLOG_FACILITY_LOCAL2,
	SYSLOG_FACILITY_LOCAL3,
	SYSLOG_FACILITY_LOCAL4,
	SYSLOG_FACILITY_LOCAL5,
	SYSLOG_FACILITY_LOCAL6,
	SYSLOG_FACILITY_LOCAL7
}       SyslogFacility;

typedef enum {
	SYSLOG_LEVEL_QUIET,
	SYSLOG_LEVEL_FATAL,
	SYSLOG_LEVEL_ERROR,
	SYSLOG_LEVEL_INFO,
	SYSLOG_LEVEL_VERBOSE,
	SYSLOG_LEVEL_DEBUG1,
	SYSLOG_LEVEL_DEBUG2,
	SYSLOG_LEVEL_DEBUG3
}       LogLevel;
/* Initializes logging. */
void    log_init(char *, LogLevel, SyslogFacility, int);

/* Logging implementation, depending on server or client */
void    do_log(LogLevel, const char *, va_list);

/* name to facility/level */
SyslogFacility log_facility_number(char *);
LogLevel log_level_number(char *);

/* Output a message to syslog or stderr */
void    fatal(const char *, ...) __attribute__((format(printf, 1, 2)));
void    error(const char *, ...) __attribute__((format(printf, 1, 2)));
void    log(const char *, ...) __attribute__((format(printf, 1, 2)));
void    verbose(const char *, ...) __attribute__((format(printf, 1, 2)));
void    debug(const char *, ...) __attribute__((format(printf, 1, 2)));
void    debug2(const char *, ...) __attribute__((format(printf, 1, 2)));
void    debug3(const char *, ...) __attribute__((format(printf, 1, 2)));

/* same as fatal() but w/o logging */
void    fatal_cleanup(void);

/*
 * Registers a cleanup function to be called by fatal()/fatal_cleanup()
 * before exiting. It is permissible to call fatal_remove_cleanup for the
 * function itself from the function.
 */
void    fatal_add_cleanup(void (*) (void *), void *);

/* Removes a cleanup function to be called at fatal(). */
void    fatal_remove_cleanup(void (*) (void *), void *);

#endif
