/*
 * Pseudo-implementation of RFC2553 name / address resolution functions
 *
 * But these functions are not implemented correctly. The minimum subset
 * is implemented for ssh use only. For exapmle, this routine assumes
 * that ai_family is AF_INET. Don't use it for another purpose.
 */

/* $Id: fake-rfc2553.h,v 1.1 2003/06/05 08:52:48 djm Exp $ */

#ifndef _FAKE_RFC2553_H
#define _FAKE_RFC2553_H

#include "includes.h"
#include "sys/types.h"

/*
 * First, socket and INET6 related definitions 
 */
#ifndef HAVE_STRUCT_SOCKADDR_STORAGE
# define	_SS_MAXSIZE	128	/* Implementation specific max size */
# define       _SS_PADSIZE     (_SS_MAXSIZE - sizeof (struct sockaddr))
struct sockaddr_storage {
	struct sockaddr	ss_sa;
	char		__ss_pad2[_SS_PADSIZE];
};
# define ss_family ss_sa.sa_family
#endif /* !HAVE_STRUCT_SOCKADDR_STORAGE */

#ifndef IN6_IS_ADDR_LOOPBACK
# define IN6_IS_ADDR_LOOPBACK(a) \
	(((u_int32_t *)(a))[0] == 0 && ((u_int32_t *)(a))[1] == 0 && \
	 ((u_int32_t *)(a))[2] == 0 && ((u_int32_t *)(a))[3] == htonl(1))
#endif /* !IN6_IS_ADDR_LOOPBACK */

#ifndef HAVE_STRUCT_IN6_ADDR
struct in6_addr {
	u_int8_t	s6_addr[16];
};
#endif /* !HAVE_STRUCT_IN6_ADDR */

#ifndef HAVE_STRUCT_SOCKADDR_IN6
struct sockaddr_in6 {
	unsigned short	sin6_family;
	u_int16_t	sin6_port;
	u_int32_t	sin6_flowinfo;
	struct in6_addr	sin6_addr;
};
#endif /* !HAVE_STRUCT_SOCKADDR_IN6 */

#ifndef AF_INET6
/* Define it to something that should never appear */
#define AF_INET6 AF_MAX
#endif

/*
 * Next, RFC2553 name / address resolution API
 */

#ifndef NI_NUMERICHOST
# define NI_NUMERICHOST    (1)
# define NI_NAMEREQD       (1<<1)
# define NI_NUMERICSERV    (1<<2)
#endif
#ifndef AI_PASSIVE
# define AI_PASSIVE		(1)
# define AI_CANONNAME		(1<<1)
# define AI_NUMERICHOST		(1<<2)
#endif

#ifndef NI_MAXSERV
# define NI_MAXSERV 32
#endif /* !NI_MAXSERV */
#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif /* !NI_MAXHOST */

#ifndef EAI_NODATA
# define EAI_NODATA	1
# define EAI_MEMORY	2
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

#ifndef HAVE_GETNAMEINFO
int getnameinfo(const struct sockaddr *, size_t, char *, size_t, 
    char *, size_t, int);
#endif /* !HAVE_GETNAMEINFO */

#endif /* !_FAKE_RFC2553_H */

