/*	$OpenBSD: match.h,v 1.8 2001/06/24 05:25:10 markus Exp $	*/

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
#ifndef MATCH_H
#define MATCH_H

int      match_pattern(const char *s, const char *pattern);
int      match_hostname(const char *host, const char *pattern, u_int len);
int	 match_host_and_ip(const char *host, const char *ip, const char *p);
int	 match_user(const char *u, const char *h, const char *i, const char *p);
char	*match_list(const char *client, const char *server, u_int *next);

#endif
