/* $OpenBSD: log.h,v 1.27 2020/10/18 11:13:45 djm Exp $ */

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

#include <stdarg.h> /* va_list */

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
	SYSLOG_FACILITY_LOCAL7,
	SYSLOG_FACILITY_NOT_SET = -1
}       SyslogFacility;

typedef enum {
	SYSLOG_LEVEL_QUIET,
	SYSLOG_LEVEL_FATAL,
	SYSLOG_LEVEL_ERROR,
	SYSLOG_LEVEL_INFO,
	SYSLOG_LEVEL_VERBOSE,
	SYSLOG_LEVEL_DEBUG1,
	SYSLOG_LEVEL_DEBUG2,
	SYSLOG_LEVEL_DEBUG3,
	SYSLOG_LEVEL_NOT_SET = -1
}       LogLevel;

typedef void (log_handler_fn)(const char *, const char *, int, LogLevel,
    const char *, void *);

void     log_init(char *, LogLevel, SyslogFacility, int);
LogLevel log_level_get(void);
int      log_change_level(LogLevel);
int      log_is_on_stderr(void);
void     log_redirect_stderr_to(const char *);
void	 log_verbose_add(const char *);
void	 log_verbose_reset(void);

SyslogFacility	log_facility_number(char *);
const char * 	log_facility_name(SyslogFacility);
LogLevel	log_level_number(char *);
const char *	log_level_name(LogLevel);

void	 set_log_handler(log_handler_fn *, void *);
void	 cleanup_exit(int) __attribute__((noreturn));

void	 sshlog(const char *, const char *, int, int,
    LogLevel, const char *, ...) __attribute__((format(printf, 6, 7)));
void	 sshlogv(const char *, const char *, int, int,
    LogLevel, const char *, va_list);
void	 sshsigdie(const char *, const char *, int, int,
    LogLevel, const char *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 6, 7)));
void	 sshlogdie(const char *, const char *, int, int,
    LogLevel, const char *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 6, 7)));
void	 sshfatal(const char *, const char *, int, int,
    LogLevel, const char *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 6, 7)));

#define ssh_nlog(level, ...)	sshlog(__FILE__, __func__, __LINE__, 0, level, __VA_ARGS__)
#define ssh_debug3(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, __VA_ARGS__)
#define ssh_debug2(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, __VA_ARGS__)
#define ssh_debug(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, __VA_ARGS__)
#define ssh_verbose(...)	sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, __VA_ARGS__)
#define ssh_log(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, __VA_ARGS__)
#define ssh_error(...)		sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, __VA_ARGS__)
#define ssh_fatal(...)		sshfatal(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_FATAL, __VA_ARGS__)
#define ssh_logdie(...)		sshlogdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, __VA_ARGS__)
#define ssh_sigdie(...)		sshsigdie(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, __VA_ARGS__)

/* Variants that prepend the caller's function */
#define ssh_nlog_f(level, ...)	sshlog(__FILE__, __func__, __LINE__, 1, level, __VA_ARGS__)
#define ssh_debug3_f(...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG3, __VA_ARGS__)
#define ssh_debug2_f(...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG2, __VA_ARGS__)
#define ssh_debug_f(...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_DEBUG1, __VA_ARGS__)
#define ssh_verbose_f(...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_VERBOSE, __VA_ARGS__)
#define ssh_log_f(...)		sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_INFO, __VA_ARGS__)
#define ssh_error_f(...)	sshlog(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, __VA_ARGS__)
#define ssh_fatal_f(...)	sshfatal(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_FATAL, __VA_ARGS__)
#define ssh_logdie_f(...)	sshlogdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, __VA_ARGS__)
#define ssh_sigdie_f(...)	sshsigdie(__FILE__, __func__, __LINE__, 1, SYSLOG_LEVEL_ERROR, __VA_ARGS__)

#define debug	ssh_debug
#define debug1	ssh_debug1
#define debug2	ssh_debug2
#define debug3	ssh_debug3
#define error	ssh_error
#define logit	ssh_log
#define verbose	ssh_verbose
#define fatal	ssh_fatal
#define logdie	ssh_logdie
#define sigdie	ssh_sigdie
#define do_log2	ssh_nlog

#endif
