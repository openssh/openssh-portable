/* $OpenBSD: canohost.c,v 1.79 2026/10/30 05:52:02 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for returning the canonical host name of the remote site.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include "xmalloc.h"
#include "log.h"
#include "addr.h"
#include "canohost.h"
#include "misc.h"

void
ipv64_normalise_mapped(struct sockaddr_storage *addr, socklen_t *len)
{
	struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)addr;
	struct sockaddr_in *a4 = (struct sockaddr_in *)addr;
	struct in_addr inaddr;
	uint16_t port;

	if (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		return;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((char *)&a6->sin6_addr) + 12, sizeof(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, sizeof(*a4));

	a4->sin_family = AF_INET;
	*len = sizeof(*a4);
	memcpy(&a4->sin_addr, &inaddr, sizeof(inaddr));
	a4->sin_port = port;
}

/*
 * Check whether an IP address is configured on one of this host's
 * interfaces. Returns 1 if it is or 0 otherwise.
 */
static int
is_local_address(struct sockaddr *sa, socklen_t salen)
{
#ifdef HAVE_IFADDRS_H
	struct ifaddrs *ifa, *ifaddrs = NULL;
	struct xaddr addr, ifaddr;
	socklen_t ifalen;
	int found = 0;

	if (addr_sa_to_xaddr(sa, salen, &addr) != 0)
		return 0;
	if (getifaddrs(&ifaddrs) != 0) {
		error_f("getifaddrs failed: %s", strerror(errno));
		return 0;
	}
	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL ||
		    ifa->ifa_addr->sa_family != sa->sa_family)
			continue;
		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			ifalen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			ifalen = sizeof(struct sockaddr_in6);
			break;
		default:
			continue;
		}
		if (addr_sa_to_xaddr(ifa->ifa_addr, ifalen, &ifaddr) == 0 &&
		    addr_cmp(&addr, &ifaddr) == 0) {
			found = 1;
			break;
		}
	}
	freeifaddrs(ifaddrs);
	return found;
#else /* HAVE_IFADDRS_H */
	return 1;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * If local_only is set then only IP addresses that are configured on this
 * host are returned; Unix domain socket paths are not.
 * The returned string must be freed.
 */
static char *
get_socket_address(int sock, int remote, int flags, int local_only)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;
	char ntop[NI_MAXHOST];
	int r;

	if (sock < 0)
		return NULL;

	/* Get IP address of client. */
	addrlen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));

	if (remote) {
		if (getpeername(sock, (struct sockaddr *)&addr, &addrlen) != 0)
			return NULL;
	} else {
		if (getsockname(sock, (struct sockaddr *)&addr, &addrlen) != 0)
			return NULL;
	}

	/* Work around Linux IPv6 weirdness */
	if (addr.ss_family == AF_INET6) {
		addrlen = sizeof(struct sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	switch (addr.ss_family) {
	case AF_INET:
	case AF_INET6:
		if (local_only &&
		    !is_local_address((struct sockaddr *)&addr, addrlen))
			return NULL;
		/* Get the address in ascii. */
		if ((r = getnameinfo((struct sockaddr *)&addr, addrlen, ntop,
		    sizeof(ntop), NULL, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			return NULL;
		}
		return xstrdup(ntop);
	case AF_UNIX:
		if (local_only)
			return NULL;
		/* Get the Unix domain socket path. */
		return xstrdup(((struct sockaddr_un *)&addr)->sun_path);
	default:
		/* We can't look up remote Unix domain sockets. */
		return NULL;
	}
}

char *
get_peer_ipaddr(int sock)
{
	char *p;

	if ((p = get_socket_address(sock, 1, NI_NUMERICHOST, 0)) != NULL)
		return p;
	return xstrdup("UNKNOWN");
}

char *
get_local_ipaddr(int sock)
{
	char *p;

	if ((p = get_socket_address(sock, 0, NI_NUMERICHOST, 0)) != NULL)
		return p;
	return xstrdup("UNKNOWN");
}

char *
get_local_name(int fd)
{
	char *host, myname[NI_MAXHOST];

	/*
	 * Assume we were passed a socket. Only trust the address if it is
	 * one of this host's: ssh-keysign(8) receives fd from an unprivileged
	 * caller that may have bound it to an arbitrary Unix domain socket
	 * path or to another host's address (e.g. via IP_FREEBIND).
	 */
	if ((host = get_socket_address(fd, 0, NI_NAMEREQD, 1)) != NULL)
		return host;

	/* Handle the case where we were passed a pipe or local socket */
	if (gethostname(myname, sizeof(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} else {
		host = xstrdup(myname);
	}

	return host;
}

/* Returns the local/remote port for the socket. */

static int
get_sock_port(int sock, int local)
{
	struct sockaddr_storage from;
	socklen_t fromlen;
	char strport[NI_MAXSERV];
	int r;

	if (sock < 0)
		return -1;
	/* Get IP address of client. */
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	if (local) {
		if (getsockname(sock, (struct sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			return 0;
		}
	} else {
		if (getpeername(sock, (struct sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			return -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	if (from.ss_family == AF_INET6)
		fromlen = sizeof(struct sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	if (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		return 0;

	/* Return port number. */
	if ((r = getnameinfo((struct sockaddr *)&from, fromlen, NULL, 0,
	    strport, sizeof(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	return atoi(strport);
}

int
get_peer_port(int sock)
{
	return get_sock_port(sock, 0);
}

int
get_local_port(int sock)
{
	return get_sock_port(sock, 1);
}
