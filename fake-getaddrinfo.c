/*
 * fake library for ssh
 *
 * This file includes getaddrinfo(), freeaddrinfo() and gai_strerror().
 * These funtions are defined in rfc2133.
 *
 * But these functions are not implemented correctly. The minimum subset
 * is implemented for ssh use only. For exapmle, this routine assumes
 * that ai_family is AF_INET. Don't use it for another purpose.
 * 
 * In the case not using 'configure --enable-ipv6', this getaddrinfo.c
 * will be used if you have broken getaddrinfo or no getaddrinfo.
 */

#include "includes.h"
#include "ssh.h"

#ifndef HAVE_GAI_STRERROR
char *
gai_strerror(ecode)
int ecode;
{
  switch (ecode) {
  case EAI_NODATA:
    return "no address associated with hostname.";
  case EAI_MEMORY:
    return "memory allocation failure.";
  default:
    return "unknown error.";
  }
}    
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
void
freeaddrinfo(ai)
struct addrinfo *ai;
{
  struct addrinfo *next;
  
  do {
    next = ai->ai_next;
    free(ai);
  } while (NULL != (ai = next));
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
static struct addrinfo *
malloc_ai(port, addr)
int port;
u_long addr;
{
  struct addrinfo *ai;

  if (NULL != (ai = (struct addrinfo *)malloc(sizeof(struct addrinfo) +
				     sizeof(struct sockaddr_in)))) {
    memset(ai, 0, sizeof(struct addrinfo) + sizeof(struct sockaddr_in));
    ai->ai_addr = (struct sockaddr *)(ai + 1);
    /* XXX -- ssh doesn't use sa_len */
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_addr->sa_family = ai->ai_family = AF_INET;
    ((struct sockaddr_in *)(ai)->ai_addr)->sin_port = port;
    ((struct sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;
    return ai;
  } else {
    return NULL;
  }
}

int
getaddrinfo(hostname, servname, hints, res)
const char *hostname, *servname;
const struct addrinfo *hints;
struct addrinfo **res;
{
  struct addrinfo *cur, *prev = NULL;
  struct hostent *hp;
  int i, port;
  
  if (servname)
    port = htons(atoi(servname));
  else
    port = 0;
  if (hints && hints->ai_flags & AI_PASSIVE)
    if (NULL != (*res = malloc_ai(port, htonl(0x00000000))))
      return 0;
    else
      return EAI_MEMORY;
  if (!hostname)
    if (NULL != (*res = malloc_ai(port, htonl(0x7f000001))))
      return 0;
    else
      return EAI_MEMORY;
  if (inet_addr(hostname) != -1)
    if (NULL != (*res = malloc_ai(port, inet_addr(hostname))))
      return 0;
    else
      return EAI_MEMORY;
  if ((hp = gethostbyname(hostname)) &&
      hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
    for (i = 0; hp->h_addr_list[i]; i++)
      if (NULL != (cur = malloc_ai(port, 
			((struct in_addr *)hp->h_addr_list[i])->s_addr))) {
	if (prev)
	  prev->ai_next = cur;
	else
	  *res = cur;
	prev = cur;
      } else {
	if (*res)
	  freeaddrinfo(*res);
	return EAI_MEMORY;
      }
    return 0;
  }
  return EAI_NODATA;
}
#endif /* !HAVE_GETADDRINFO */
