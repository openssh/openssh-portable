/*

canohost.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun Jul  2 17:52:22 1995 ylo

Functions for returning the canonical host name of the remote site.

*/

#include "includes.h"
RCSID("$Id: canohost.c,v 1.1 1999/10/27 03:42:43 damien Exp $");

#include "packet.h"
#include "xmalloc.h"
#include "ssh.h"

/* Return the canonical name of the host at the other end of the socket. 
   The caller should free the returned string with xfree. */

char *get_remote_hostname(int socket)
{
  struct sockaddr_in from;
  int fromlen, i;
  struct hostent *hp;
  char name[MAXHOSTNAMELEN];

  /* Get IP address of client. */
  fromlen = sizeof(from);
  memset(&from, 0, sizeof(from));
  if (getpeername(socket, (struct sockaddr *)&from, &fromlen) < 0)
    {
      error("getpeername failed: %.100s", strerror(errno));
      strlcpy(name, "UNKNOWN", sizeof name);
      goto check_ip_options;
    }
  
  /* Map the IP address to a host name. */
  hp = gethostbyaddr((char *)&from.sin_addr, sizeof(struct in_addr),
		     from.sin_family);
  if (hp)
    {
      /* Got host name, find canonic host name. */
      if (strchr(hp->h_name, '.') != 0)
	strlcpy(name, hp->h_name, sizeof(name));
      else if (hp->h_aliases != 0
	       && hp->h_aliases[0] != 0
	       && strchr(hp->h_aliases[0], '.') != 0)
	strlcpy(name, hp->h_aliases[0], sizeof(name));
      else
	strlcpy(name, hp->h_name, sizeof(name));
      
      /* Convert it to all lowercase (which is expected by the rest of this
	 software). */
      for (i = 0; name[i]; i++)
	if (isupper(name[i]))
	  name[i] = tolower(name[i]);

      /* Map it back to an IP address and check that the given address actually
	 is an address of this host.  This is necessary because anyone with
	 access to a name server can define arbitrary names for an IP address.
	 Mapping from name to IP address can be trusted better (but can still
	 be fooled if the intruder has access to the name server of the
	 domain). */
      hp = gethostbyname(name);
      if (!hp)
	{
	  log("reverse mapping checking gethostbyname for %.700s failed - POSSIBLE BREAKIN ATTEMPT!", name);
	  strlcpy(name, inet_ntoa(from.sin_addr), sizeof name);
	  goto check_ip_options;
	}
      /* Look for the address from the list of addresses. */
      for (i = 0; hp->h_addr_list[i]; i++)
	if (memcmp(hp->h_addr_list[i], &from.sin_addr, sizeof(from.sin_addr))
	    == 0)
	  break;
      /* If we reached the end of the list, the address was not there. */
      if (!hp->h_addr_list[i])
	{
	  /* Address not found for the host name. */
	  log("Address %.100s maps to %.600s, but this does not map back to the address - POSSIBLE BREAKIN ATTEMPT!",
	      inet_ntoa(from.sin_addr), name);
	  strlcpy(name, inet_ntoa(from.sin_addr), sizeof name);
	  goto check_ip_options;
	}
      /* Address was found for the host name.  We accept the host name. */
    }
  else
    {
      /* Host name not found.  Use ascii representation of the address. */
      strlcpy(name, inet_ntoa(from.sin_addr), sizeof name);
      log("Could not reverse map address %.100s.", name);
    }

 check_ip_options:
  
  /* If IP options are supported, make sure there are none (log and clear
     them if any are found).  Basically we are worried about source routing;
     it can be used to pretend you are somebody (ip-address) you are not.
     That itself may be "almost acceptable" under certain circumstances,
     but rhosts autentication is useless if source routing is accepted.
     Notice also that if we just dropped source routing here, the other
     side could use IP spoofing to do rest of the interaction and could still
     bypass security.  So we exit here if we detect any IP options. */
  {
    unsigned char options[200], *ucp;
    char text[1024], *cp;
    int option_size, ipproto;
    struct protoent *ip;
    
    if ((ip = getprotobyname("ip")) != NULL)
      ipproto = ip->p_proto;
    else
      ipproto = IPPROTO_IP;
    option_size = sizeof(options);
    if (getsockopt(0, ipproto, IP_OPTIONS, (char *)options,
		   &option_size) >= 0 && option_size != 0)
      {
	cp = text;
	/* Note: "text" buffer must be at least 3x as big as options. */
	for (ucp = options; option_size > 0; ucp++, option_size--, cp += 3)
	  sprintf(cp, " %2.2x", *ucp);
	log("Connection from %.100s with IP options:%.800s",
	    inet_ntoa(from.sin_addr), text);
	packet_disconnect("Connection from %.100s with IP options:%.800s", 
			  inet_ntoa(from.sin_addr), text);
      }
  }

  return xstrdup(name);
}

static char *canonical_host_name = NULL;
static char *canonical_host_ip = NULL;

/* Return the canonical name of the host in the other side of the current
   connection.  The host name is cached, so it is efficient to call this 
   several times. */

const char *get_canonical_hostname()
{
  /* Check if we have previously retrieved this same name. */
  if (canonical_host_name != NULL)
    return canonical_host_name;

  /* Get the real hostname if socket; otherwise return UNKNOWN. */
  if (packet_get_connection_in() == packet_get_connection_out())
    canonical_host_name = get_remote_hostname(packet_get_connection_in());
  else
    canonical_host_name = xstrdup("UNKNOWN");

  return canonical_host_name;
}

/* Returns the IP-address of the remote host as a string.  The returned
   string need not be freed. */

const char *get_remote_ipaddr()
{
  struct sockaddr_in from;
  int fromlen, socket;

  /* Check if we have previously retrieved this same name. */
  if (canonical_host_ip != NULL)
    return canonical_host_ip;

  /* If not a socket, return UNKNOWN. */
  if (packet_get_connection_in() != packet_get_connection_out())
    {
      canonical_host_ip = xstrdup("UNKNOWN");
      return canonical_host_ip;
    }

  /* Get client socket. */
  socket = packet_get_connection_in();

  /* Get IP address of client. */
  fromlen = sizeof(from);
  memset(&from, 0, sizeof(from));
  if (getpeername(socket, (struct sockaddr *)&from, &fromlen) < 0)
    {
      error("getpeername failed: %.100s", strerror(errno));
      return NULL;
    }

  /* Get the IP address in ascii. */
  canonical_host_ip = xstrdup(inet_ntoa(from.sin_addr));

  /* Return ip address string. */
  return canonical_host_ip;
}

/* Returns the port of the peer of the socket. */

int get_peer_port(int sock)
{
  struct sockaddr_in from;
  int fromlen;

  /* Get IP address of client. */
  fromlen = sizeof(from);
  memset(&from, 0, sizeof(from));
  if (getpeername(sock, (struct sockaddr *)&from, &fromlen) < 0)
    {
      error("getpeername failed: %.100s", strerror(errno));
      return 0;
    }

  /* Return port number. */
  return ntohs(from.sin_port);
}

/* Returns the port number of the remote host.  */

int get_remote_port()
{
  int socket;

  /* If the connection is not a socket, return 65535.  This is intentionally
     chosen to be an unprivileged port number. */
  if (packet_get_connection_in() != packet_get_connection_out())
    return 65535;

  /* Get client socket. */
  socket = packet_get_connection_in();

  /* Get and return the peer port number. */
  return get_peer_port(socket);
}
