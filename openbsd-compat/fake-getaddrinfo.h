/* $Id: fake-getaddrinfo.h,v 1.6 2003/06/05 00:04:12 djm Exp $ */

#ifndef _FAKE_GETADDRINFO_H
#define _FAKE_GETADDRINFO_H

#include "config.h"

#include "fake-gai-errnos.h"

#ifndef AI_PASSIVE
# define AI_PASSIVE		(1)
# define AI_CANONNAME		(1<<1)
# define AI_NUMERICHOST		(1<<2)
#endif

#ifndef HAVE_STRUCT_ADDRINFO
struct addrinfo {
	int	ai_flags;	/* AI_PASSIVE, AI_CANONNAME */
	int	ai_family;	/* PF_xxx */
	int	ai_socktype;	/* SOCK_xxx */
	int	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	size_t	ai_addrlen;	/* length of ai_addr */
	char	*ai_canonname;	/* canonical name for hostname */
	struct sockaddr *ai_addr;	/* binary address */
	struct addrinfo *ai_next;	/* next structure in linked list */
};
#endif /* !HAVE_STRUCT_ADDRINFO */

#ifndef HAVE_GETADDRINFO
int getaddrinfo(const char *, const char *, 
    const struct addrinfo *, struct addrinfo **);
#endif /* !HAVE_GETADDRINFO */

#ifndef HAVE_GAI_STRERROR
char *gai_strerror(int);
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
void freeaddrinfo(struct addrinfo *);
#endif /* !HAVE_FREEADDRINFO */

#endif /* _FAKE_GETADDRINFO_H */
