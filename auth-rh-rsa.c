/*

auth-rh-rsa.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun May  7 03:08:06 1995 ylo

Rhosts or /etc/hosts.equiv authentication combined with RSA host
authentication.

*/

#include "includes.h"
RCSID("$Id: auth-rh-rsa.c,v 1.1 1999/10/27 03:42:43 damien Exp $");

#include "packet.h"
#include "ssh.h"
#include "xmalloc.h"
#include "uidswap.h"

/* Tries to authenticate the user using the .rhosts file and the host using
   its host key.  Returns true if authentication succeeds. 
   .rhosts and .shosts will be ignored if ignore_rhosts is non-zero. */

int auth_rhosts_rsa(struct passwd *pw, const char *client_user,
		    unsigned int client_host_key_bits,
		    BIGNUM *client_host_key_e, BIGNUM *client_host_key_n,
		    int ignore_rhosts, int strict_modes)
{
  const char *canonical_hostname;
  HostStatus host_status;
  BIGNUM *ke, *kn;

  debug("Trying rhosts with RSA host authentication for %.100s", client_user);

  /* Check if we would accept it using rhosts authentication. */
  if (!auth_rhosts(pw, client_user, ignore_rhosts, strict_modes))
    return 0;

  canonical_hostname = get_canonical_hostname();

  debug("Rhosts RSA authentication: canonical host %.900s",
	canonical_hostname);
  
  /* Check if we know the host and its host key. */
  /* Check system-wide host file. */
  ke = BN_new();
  kn = BN_new();
  host_status = check_host_in_hostfile(SSH_SYSTEM_HOSTFILE, canonical_hostname,
				       client_host_key_bits, client_host_key_e,
				       client_host_key_n, ke, kn);
  BN_free(ke);
  BN_free(kn);
  if (host_status != HOST_OK) {
    /* The host key was not found. */
    debug("Rhosts with RSA host authentication denied: unknown or invalid host key");
    packet_send_debug("Your host key cannot be verified: unknown or invalid host key.");
    return 0;
  }

  /* A matching host key was found and is known. */
  
  /* Perform the challenge-response dialog with the client for the host key. */
  if (!auth_rsa_challenge_dialog(client_host_key_bits,
				 client_host_key_e, client_host_key_n))
    {
      log("Client on %.800s failed to respond correctly to host authentication.",
	  canonical_hostname);
      return 0;
    }

  /* We have authenticated the user using .rhosts or /etc/hosts.equiv, and
     the host using RSA.  We accept the authentication. */
  
  log("Rhosts with RSA host authentication accepted for %.100s, %.100s on %.700s.",
      pw->pw_name, client_user, canonical_hostname);
  packet_send_debug("Rhosts with RSA host authentication accepted.");
  return 1;
}
