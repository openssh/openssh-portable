/*
 * fake library for ssh
 *
 * This file includes getnameinfo().
 * These funtions are defined in rfc2133.
 *
 * But these functions are not implemented correctly. The minimum subset
 * is implemented for ssh use only. For exapmle, this routine assumes
 * that ai_family is AF_INET. Don't use it for another purpose.
 */

#include "includes.h"
#include "ssh.h"

RCSID("$Id: fake-getnameinfo.c,v 1.3 2003/05/18 14:13:39 djm Exp $");

#ifndef HAVE_GETNAMEINFO
int getnameinfo(const struct sockaddr *sa, size_t salen, char *host, 
                size_t hostlen, char *serv, size_t servlen, int flags)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct hostent *hp;
	char tmpserv[16];

	if (serv != NULL) {
		snprintf(tmpserv, sizeof(tmpserv), "%d", ntohs(sin->sin_port));
		if (strlcpy(serv, tmpserv, servlen) >= servlen)
			return (EAI_MEMORY);
	}

	if (host != NULL) {
		if (flags & NI_NUMERICHOST) {
			if (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				return (EAI_MEMORY);
			else
				return (0);
		} else {
			hp = gethostbyaddr((char *)&sin->sin_addr, 
			    sizeof(struct in_addr), AF_INET);
			if (hp == NULL)
				return (EAI_NODATA);
			
			if (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				return (EAI_MEMORY);
			else
				return (0);
		}
	}
	return (0);
}
#endif /* !HAVE_GETNAMEINFO */
