/*
 * fake library for ssh
 *
 * This file is included in getaddrinfo.c and getnameinfo.c.
 * See getaddrinfo.c and getnameinfo.c.
 */

#ifndef _FAKE_GAI_ERRNOS_H
#define _FAKE_GAI_ERRNOS_H

/* $Id: fake-gai-errnos.h,v 1.3 2003/05/18 14:13:39 djm Exp $ */

/* for old netdb.h */
#ifndef EAI_NODATA
# define EAI_NODATA	1
# define EAI_MEMORY	2
#endif

#endif /* !_FAKE_GAI_ERRNOS_H */
