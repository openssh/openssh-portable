/*	$OpenBSD: canohost.h,v 1.4 2001/02/03 10:08:37 markus Exp $	*/

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

/*
 * Return the canonical name of the host in the other side of the current
 * connection (as returned by packet_get_connection).  The host name is
 * cached, so it is efficient to call this several times.
 */
const char *get_canonical_hostname(int reverse_mapping_check);

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string is cached and must not be freed.
 */
const char *get_remote_ipaddr(void);

/* Returns the ipaddr/port number of the peer of the socket. */
char *	get_peer_ipaddr(int socket);
int     get_peer_port(int sock);

/* Returns the port number of the remote/local host. */
int     get_remote_port(void);
int	get_local_port(void);
