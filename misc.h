/*	$OpenBSD: misc.h,v 1.8 2001/05/19 19:43:57 stevesk Exp $	*/

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
/* remove newline at end of string */
char	*chop(char *s);

/* return next token in configuration line */
char	*strdelim(char **s);

/* set/unset filedescriptor to non-blocking */
void	set_nonblock(int fd);
void	unset_nonblock(int fd);

struct passwd * pwcopy(struct passwd *pw);

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >0 and <=65535.
 * Return 0 if invalid.
 */
int a2port(const char *s);

/* code from scp.c/rcp.c */
char *cleanhostname(char *host);
char *colon(char *cp);

/*
 * Convert a time string into seconds; format is
 * a sequence of:
 *	time[qualifier]
 *
 * Valid time qualifiers are:
 *	<none>	seconds
 *	s|S	seconds
 *	m|M	minutes
 *	h|H	hours
 *	d|D	days
 *	w|W	weeks
 *
 * Examples:
 *	90m	90 minutes
 *	1h30m	90 minutes
 *	2d	2 days
 *	1w	1 week
 *
 * Return -1 if time string is invalid.
 */

long convtime(const char *s);

/* function to assist building execv() arguments */
typedef struct arglist arglist;
struct arglist {
        char    **list;
        int     num;
        int     nalloc;
};

void addargs(arglist *args, char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* wrapper for signal interface */
typedef void (*mysig_t)(int);
mysig_t mysignal(int sig, mysig_t act);
