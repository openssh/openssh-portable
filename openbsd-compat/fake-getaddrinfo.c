/*
 * fake library for ssh
 *
 * This file includes getaddrinfo(), freeaddrinfo() and gai_strerror().
 * These funtions are defined in rfc2133.
 *
 * But these functions are not implemented correctly. The minimum subset
 * is implemented for ssh use only. For exapmle, this routine assumes
 * that ai_family is AF_INET. Don't use it for another purpose.
 */

#include "includes.h"
#include "xmalloc.h"
#include "ssh.h"

RCSID("$Id: fake-getaddrinfo.c,v 1.8 2003/05/19 00:39:37 djm Exp $");

#ifndef HAVE_GAI_STRERROR
char *
gai_strerror(int err)
{
	switch (err) {
	case EAI_NODATA:
		return ("no address associated with name");
	case EAI_MEMORY:
		return ("memory allocation failure.");
	default:
		return ("unknown/invalid error.");
	}
}    
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
void
freeaddrinfo(struct addrinfo *ai)
{
	struct addrinfo *next;

	for(; ai != NULL;) {
		next = ai->ai_next;
		free(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
static struct
addrinfo *malloc_ai(int port, u_long addr, const struct addrinfo *hints)
{
	struct addrinfo *ai;

	ai = xmalloc(sizeof(*ai) + sizeof(struct sockaddr_in));
	
	memset(ai, '\0', sizeof(*ai) + sizeof(struct sockaddr_in));
	
	ai->ai_addr = (struct sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = sizeof(struct sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((struct sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((struct sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;
	
	/* XXX: the following is not generally correct, but does what we want */
	if (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	else
		ai->ai_socktype = SOCK_STREAM;

	if (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	return (ai);
}

int
getaddrinfo(const char *hostname, const char *servname, 
    const struct addrinfo *hints, struct addrinfo **res)
{
	struct hostent *hp;
	struct servent *sp;
	struct in_addr in;
	int i;
	long int port;
	u_long addr;

	port = 0;
	if (servname != NULL) {
		char *cp;

		port = strtol(servname, &cp, 10);
		if (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		else if ((sp = getservbyname(servname, NULL)) != NULL)
			port = sp->s_port;
		else
			port = 0;
	}

	if (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		if (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		return (0);
	}
		
	if (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		return (0);
	}
	
	if (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		return (0);
	}
	
	hp = gethostbyname(hostname);
	if (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		struct addrinfo *cur, *prev;

		cur = prev = NULL;
		for (i = 0; hp->h_addr_list[i]; i++) {
			struct in_addr *in = (struct in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			if (prev)
				prev->ai_next = cur;
			else
				*res = cur;

			prev = cur;
		}
		return (0);
	}
	
	return (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
