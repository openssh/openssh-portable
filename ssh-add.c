/*

ssh-add.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Thu Apr  6 00:52:24 1995 ylo

Adds an identity to the authentication server, or removes an identity.

*/

#include "includes.h"
RCSID("$Id: ssh-add.c,v 1.1 1999/10/27 03:42:45 damien Exp $");

#include "rsa.h"
#include "ssh.h"
#include "xmalloc.h"
#include "authfd.h"

void
delete_file(const char *filename)
{
  RSA *key;
  char *comment;
  AuthenticationConnection *ac;

  key = RSA_new();
  if (!load_public_key(filename, key, &comment))
    {
      printf("Bad key file %s: %s\n", filename, strerror(errno));
      return;
    }

  /* Send the request to the authentication agent. */
  ac = ssh_get_authentication_connection();
  if (!ac)
    {
      fprintf(stderr,
	      "Could not open a connection to your authentication agent.\n");
      RSA_free(key);
      xfree(comment);
      return;
    }
  if (ssh_remove_identity(ac, key))
    fprintf(stderr, "Identity removed: %s (%s)\n", filename, comment);
  else
    fprintf(stderr, "Could not remove identity: %s\n", filename);
  RSA_free(key);
  xfree(comment);
  ssh_close_authentication_connection(ac);
}

void
delete_all()
{
  AuthenticationConnection *ac;
  
  /* Get a connection to the agent. */
  ac = ssh_get_authentication_connection();
  if (!ac)
    {
      fprintf(stderr,
	      "Could not open a connection to your authentication agent.\n");
      return;
    }

  /* Send a request to remove all identities. */
  if (ssh_remove_all_identities(ac))
    fprintf(stderr, "All identities removed.\n");
  else
    fprintf(stderr, "Failed to remove all identitities.\n");
  
  /* Close the connection to the agent. */
  ssh_close_authentication_connection(ac);
}

void
add_file(const char *filename)
{
  RSA *key;
  RSA *public_key;
  AuthenticationConnection *ac;
  char *saved_comment, *comment, *pass;
  int first;
  
  key = RSA_new();
  public_key = RSA_new();
  if (!load_public_key(filename, public_key, &saved_comment))
    {
      printf("Bad key file %s: %s\n", filename, strerror(errno));
      return;
    }
  RSA_free(public_key);
  
  pass = xstrdup("");
  first = 1;
  while (!load_private_key(filename, pass, key, &comment))
    {
      /* Free the old passphrase. */
      memset(pass, 0, strlen(pass));
      xfree(pass);

      /* Ask for a passphrase. */
      if (getenv("DISPLAY") && !isatty(fileno(stdin)))
	{
	      xfree(saved_comment);
	      return;
	}
      else
	{
	  if (first)
	    printf("Need passphrase for %s (%s).\n", filename, saved_comment);
	  else
	    printf("Bad passphrase.\n");
	  pass = read_passphrase("Enter passphrase: ", 1);
	  if (strcmp(pass, "") == 0)
	    {
	      xfree(saved_comment);
	      xfree(pass);
	      return;
	    }
	}
      first = 0;
    }
  memset(pass, 0, strlen(pass));
  xfree(pass);

  xfree(saved_comment);

  /* Send the key to the authentication agent. */
  ac = ssh_get_authentication_connection();
  if (!ac)
    {
      fprintf(stderr,
	      "Could not open a connection to your authentication agent.\n");
      RSA_free(key);
      xfree(comment);
      return;
    }
  if (ssh_add_identity(ac, key, comment))
    fprintf(stderr, "Identity added: %s (%s)\n", filename, comment);
  else
    fprintf(stderr, "Could not add identity: %s\n", filename);
  RSA_free(key);
  xfree(comment);
  ssh_close_authentication_connection(ac);
}

void
list_identities()
{
  AuthenticationConnection *ac;
  BIGNUM *e, *n;
  int bits, status;
  char *comment;
  int had_identities;

  ac = ssh_get_authentication_connection();
  if (!ac)
    {
      fprintf(stderr, "Could not connect to authentication server.\n");
      return;
    }
  e = BN_new();
  n = BN_new();
  had_identities = 0;
  for (status = ssh_get_first_identity(ac, &bits, e, n, &comment);
       status;
       status = ssh_get_next_identity(ac, &bits, e, n, &comment))
    {
      char *buf;
      had_identities = 1;
      printf("%d ", bits);
      buf = BN_bn2dec(e);
      assert(buf != NULL);
      printf("%s ", buf);
      free (buf);
      buf = BN_bn2dec(n);
      assert(buf != NULL);
      printf("%s %s\n", buf, comment);
      free (buf);
      xfree(comment);
    }
  BN_clear_free(e);
  BN_clear_free(n);
  if (!had_identities)
    printf("The agent has no identities.\n");
  ssh_close_authentication_connection(ac);
}

int
main(int ac, char **av)
{
  struct passwd *pw;
  char buf[1024];
  int no_files = 1;
  int i;
  int deleting = 0;

  /* check if RSA support exists */
  if (rsa_alive() == 0) {
    extern char *__progname;

    fprintf(stderr,
      "%s: no RSA support in libssl and libcrypto.  See ssl(8).\n",
      __progname);
    exit(1);
  }

  for (i = 1; i < ac; i++)
    {
      if (strcmp(av[i], "-l") == 0)
	{
	  list_identities();
	  no_files = 0; /* Don't default-add/delete if -l. */
	  continue;
	}
      if (strcmp(av[i], "-d") == 0)
	{
	  deleting = 1;
	  continue;
	}
      if (strcmp(av[i], "-D") == 0)
	{
	  delete_all();
	  no_files = 0;
	  continue;
	}
      no_files = 0;
      if (deleting)
	delete_file(av[i]);
      else
	add_file(av[i]);
    }
  if (no_files)
    {
      pw = getpwuid(getuid());
      if (!pw)
	{
	  fprintf(stderr, "No user found with uid %d\n", (int)getuid());
	  exit(1);
	}
      snprintf(buf, sizeof buf, "%s/%s", pw->pw_dir, SSH_CLIENT_IDENTITY);
      if (deleting)
	delete_file(buf);
      else
	add_file(buf);
    }
  exit(0);
}
