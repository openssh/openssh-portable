/*	$OpenBSD: misc.h,v 1.9 2001/06/26 06:32:56 itojun Exp $	*/

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
char	*chop(char *);

/* return next token in configuration line */
char	*strdelim(char **);

/* set/unset filedescriptor to non-blocking */
void	set_nonblock(int);
void	unset_nonblock(int);

struct passwd * pwcopy(struct passwd *);

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >0 and <=65535.
 * Return 0 if invalid.
 */
int a2port(const char *);

/* code from scp.c/rcp.c */
char *cleanhostname(char *);
char *colon(char *);

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

long convtime(const char *);

/* function to assist building execv() arguments */
typedef struct arglist arglist;
struct arglist {
        char    **list;
        int     num;
        int     nalloc;
};

void addargs(arglist *, char *, ...) __attribute__((format(printf, 2, 3)));

/* wrapper for signal interface */
typedef void (*mysig_t)(int);
mysig_t mysignal(int sig, mysig_t act);
