/*

tildexpand.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Wed Jul 12 01:07:36 1995 ylo

*/

#include "includes.h"
RCSID("$Id: tildexpand.c,v 1.1 1999/10/27 03:42:46 damien Exp $");

#include "xmalloc.h"
#include "ssh.h"

/* Expands tildes in the file name.  Returns data allocated by xmalloc.
   Warning: this calls getpw*. */

char *tilde_expand_filename(const char *filename, uid_t my_uid)
{
  const char *cp;
  unsigned int userlen;
  char *expanded;
  struct passwd *pw;
  char user[100];

  /* Return immediately if no tilde. */
  if (filename[0] != '~')
    return xstrdup(filename);

  /* Skip the tilde. */
  filename++;

  /* Find where the username ends. */
  cp = strchr(filename, '/');
  if (cp)
    userlen = cp - filename;  /* Have something after username. */
  else
    userlen = strlen(filename); /* Nothign after username. */
  if (userlen == 0)
    pw = getpwuid(my_uid);  /* Own home directory. */
  else
    {
      /* Tilde refers to someone elses home directory. */
      if (userlen > sizeof(user) - 1)
	fatal("User name after tilde too long.");
      memcpy(user, filename, userlen);
      user[userlen] = 0;
      pw = getpwnam(user);
    }

  /* Check that we found the user. */
  if (!pw)
    fatal("Unknown user %100s.", user);
  
  /* If referring to someones home directory, return it now. */
  if (!cp)
    { /* Only home directory specified */
      return xstrdup(pw->pw_dir);
    }
  
  /* Build a path combining the specified directory and path. */
  expanded = xmalloc(strlen(pw->pw_dir) + strlen(cp + 1) + 2);
  sprintf(expanded, "%s/%s", pw->pw_dir, cp + 1);
  return expanded;
}
