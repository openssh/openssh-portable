/*

ssh-keygen.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1994 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Mar 27 02:26:40 1995 ylo

Identity and host key generation and maintenance.

*/

#include "includes.h"
RCSID("$Id: ssh-keygen.c,v 1.1 1999/10/27 03:42:45 damien Exp $");

#include "rsa.h"
#include "ssh.h"
#include "xmalloc.h"

/* Generated private key. */
RSA *private_key;

/* Generated public key. */
RSA *public_key;

/* Number of bits in the RSA key.  This value can be changed on the command
   line. */
int bits = 1024;

/* Flag indicating that we just want to change the passphrase.  This can be
   set on the command line. */
int change_passphrase = 0;

/* Flag indicating that we just want to change the comment.  This can be set
   on the command line. */
int change_comment = 0;

int quiet = 0;

/* This is set to the identity file name if given on the command line. */
char *identity_file = NULL;

/* This is set to the passphrase if given on the command line. */
char *identity_passphrase = NULL;

/* This is set to the new passphrase if given on the command line. */
char *identity_new_passphrase = NULL;

/* This is set to the new comment if given on the command line. */
char *identity_comment = NULL;

/* Perform changing a passphrase.  The argument is the passwd structure
   for the current user. */

void
do_change_passphrase(struct passwd *pw)
{
  char buf[1024], *comment;
  char *old_passphrase, *passphrase1, *passphrase2;
  struct stat st;
  RSA *private_key;

  /* Read key file name. */
  if (identity_file != NULL) {
      strncpy(buf, identity_file, sizeof(buf));
      buf[sizeof(buf) - 1] = '\0';
  } else {
    printf("Enter file in which the key is ($HOME/%s): ", SSH_CLIENT_IDENTITY);
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin) == NULL)
      exit(1);
    if (strchr(buf, '\n'))
      *strchr(buf, '\n') = 0;
    if (strcmp(buf, "") == 0)
      snprintf(buf, sizeof buf, "%s/%s", pw->pw_dir, SSH_CLIENT_IDENTITY);
  }

  /* Check if the file exists. */
  if (stat(buf, &st) < 0)
    {
      perror(buf);
      exit(1);
    }
  
  /* Try to load the public key from the file the verify that it is
     readable and of the proper format. */
  public_key = RSA_new();
  if (!load_public_key(buf, public_key, NULL))
    {
      printf("%s is not a valid key file.\n", buf);
      exit(1);
    }
  /* Clear the public key since we are just about to load the whole file. */
  RSA_free(public_key);

  /* Try to load the file with empty passphrase. */
  private_key = RSA_new();
  if (!load_private_key(buf, "", private_key, &comment)) {
    /* Read passphrase from the user. */
    if (identity_passphrase)
      old_passphrase = xstrdup(identity_passphrase);
    else
      old_passphrase = read_passphrase("Enter old passphrase: ", 1);
    /* Try to load using the passphrase. */
    if (!load_private_key(buf, old_passphrase, private_key, &comment))
      {
	memset(old_passphrase, 0, strlen(old_passphrase));
	xfree(old_passphrase);
	printf("Bad passphrase.\n");
	exit(1);
      }
    /* Destroy the passphrase. */
    memset(old_passphrase, 0, strlen(old_passphrase));
    xfree(old_passphrase);
  }
  printf("Key has comment '%s'\n", comment);
  
  /* Ask the new passphrase (twice). */
  if (identity_new_passphrase)
    {
      passphrase1 = xstrdup(identity_new_passphrase);
      passphrase2 = NULL;
    }
  else
    {
      passphrase1 = 
	read_passphrase("Enter new passphrase (empty for no passphrase): ", 1);
      passphrase2 = read_passphrase("Enter same passphrase again: ", 1);

      /* Verify that they are the same. */
      if (strcmp(passphrase1, passphrase2) != 0)
	{
	  memset(passphrase1, 0, strlen(passphrase1));
	  memset(passphrase2, 0, strlen(passphrase2));
	  xfree(passphrase1);
	  xfree(passphrase2);
	  printf("Pass phrases do not match.  Try again.\n");
	  exit(1);
	}
      /* Destroy the other copy. */
      memset(passphrase2, 0, strlen(passphrase2));
      xfree(passphrase2);
    }

  /* Save the file using the new passphrase. */
  if (!save_private_key(buf, passphrase1, private_key, comment))
    {
      printf("Saving the key failed: %s: %s.\n",
	     buf, strerror(errno));
      memset(passphrase1, 0, strlen(passphrase1));
      xfree(passphrase1);
      RSA_free(private_key);
      xfree(comment);
      exit(1);
    }
  /* Destroy the passphrase and the copy of the key in memory. */
  memset(passphrase1, 0, strlen(passphrase1));
  xfree(passphrase1);
  RSA_free(private_key); /* Destroys contents */
  xfree(comment);

  printf("Your identification has been saved with the new passphrase.\n");
  exit(0);
}

/* Change the comment of a private key file. */

void
do_change_comment(struct passwd *pw)
{
  char buf[1024], new_comment[1024], *comment;
  RSA *private_key;
  char *passphrase;
  struct stat st;
  FILE *f;
  char *tmpbuf;

  /* Read key file name. */
  if (identity_file)
    {
      strncpy(buf, identity_file, sizeof(buf));
      buf[sizeof(buf) - 1] = '\0';
    }
  else
    {
      printf("Enter file in which the key is ($HOME/%s): ", 
	     SSH_CLIENT_IDENTITY);
      fflush(stdout);
      if (fgets(buf, sizeof(buf), stdin) == NULL)
	exit(1);
      if (strchr(buf, '\n'))
	*strchr(buf, '\n') = 0;
      if (strcmp(buf, "") == 0)
	snprintf(buf, sizeof buf, "%s/%s", pw->pw_dir, SSH_CLIENT_IDENTITY);
    }

  /* Check if the file exists. */
  if (stat(buf, &st) < 0)
    {
      perror(buf);
      exit(1);
    }
  
  /* Try to load the public key from the file the verify that it is
     readable and of the proper format. */
  public_key = RSA_new();
  if (!load_public_key(buf, public_key, NULL))
    {
      printf("%s is not a valid key file.\n", buf);
      exit(1);
    }

  private_key = RSA_new();
  /* Try to load the file with empty passphrase. */
  if (load_private_key(buf, "", private_key, &comment))
    passphrase = xstrdup("");
  else
    {
      /* Read passphrase from the user. */
      if (identity_passphrase)
	passphrase = xstrdup(identity_passphrase);
      else
	if (identity_new_passphrase)
	  passphrase = xstrdup(identity_new_passphrase);
	else
	  passphrase = read_passphrase("Enter passphrase: ", 1);
      /* Try to load using the passphrase. */
      if (!load_private_key(buf, passphrase, private_key, &comment))
	{
	  memset(passphrase, 0, strlen(passphrase));
	  xfree(passphrase);
	  printf("Bad passphrase.\n");
	  exit(1);
	}
    }
  printf("Key now has comment '%s'\n", comment);

  if (identity_comment)
    {
      strncpy(new_comment, identity_comment, sizeof(new_comment));
      new_comment[sizeof(new_comment) - 1] = '\0';
    }
  else
    {
      printf("Enter new comment: ");
      fflush(stdout);
      if (!fgets(new_comment, sizeof(new_comment), stdin))
	{
	  memset(passphrase, 0, strlen(passphrase));
	  RSA_free(private_key);
	  exit(1);
	}
      
      /* Remove terminating newline from comment. */
      if (strchr(new_comment, '\n'))
	*strchr(new_comment, '\n') = 0;
    }
      
  /* Save the file using the new passphrase. */
  if (!save_private_key(buf, passphrase, private_key, new_comment))
    {
      printf("Saving the key failed: %s: %s.\n",
	     buf, strerror(errno));
      memset(passphrase, 0, strlen(passphrase));
      xfree(passphrase);
      RSA_free(private_key);
      xfree(comment);
      exit(1);
    }

  /* Destroy the passphrase and the private key in memory. */
  memset(passphrase, 0, strlen(passphrase));
  xfree(passphrase);
  RSA_free(private_key);

  /* Save the public key in text format in a file with the same name but
     .pub appended. */
  strcat(buf, ".pub");
  f = fopen(buf, "w");
  if (!f)
    {
      printf("Could not save your public key in %s\n", buf);
      exit(1);
    }
  fprintf(f, "%d ", BN_num_bits(public_key->n));
  tmpbuf = BN_bn2dec(public_key->e);
  fprintf(f, "%s ", tmpbuf);
  free (tmpbuf);
  tmpbuf = BN_bn2dec(public_key->n);
  fprintf(f, "%s %s\n", tmpbuf, new_comment);
  free (tmpbuf);
  fclose(f);

  xfree(comment);

  printf("The comment in your key file has been changed.\n");
  exit(0);
}

/* Main program for key management. */

int
main(int ac, char **av)
{
  char buf[16384], buf2[1024], *passphrase1, *passphrase2;
  struct passwd *pw;
  char *tmpbuf;
  int opt;
  struct stat st;
  FILE *f;
  char hostname[MAXHOSTNAMELEN];
  extern int optind;
  extern char *optarg;

  /* check if RSA support exists */
  if (rsa_alive() == 0) {
    extern char *__progname;

    fprintf(stderr,
      "%s: no RSA support in libssl and libcrypto.  See ssl(8).\n",
      __progname);
    exit(1);
  }

  /* Get user\'s passwd structure.  We need this for the home directory. */
  pw = getpwuid(getuid());
  if (!pw)
    {
      printf("You don't exist, go away!\n");
      exit(1);
    }

  /* Create ~/.ssh directory if it doesn\'t already exist. */
  snprintf(buf, sizeof buf, "%s/%s", pw->pw_dir, SSH_USER_DIR);
  if (stat(buf, &st) < 0)
    if (mkdir(buf, 0755) < 0)
      error("Could not create directory '%s'.", buf);

  /* Parse command line arguments. */
  while ((opt = getopt(ac, av, "qpcb:f:P:N:C:")) != EOF)
    {
      switch (opt)
	{
	case 'b':
	  bits = atoi(optarg);
	  if (bits < 512 || bits > 32768)
	    {
	      printf("Bits has bad value.\n");
	      exit(1);
	    }
	  break;

	case 'p':
	  change_passphrase = 1;
	  break;

	case 'c':
	  change_comment = 1;
	  break;

	case 'f':
	  identity_file = optarg;
	  break;
	  
	case 'P':
	  identity_passphrase = optarg;
	  break;

	case 'N':
	  identity_new_passphrase = optarg;
	  break;

	case 'C':
	  identity_comment = optarg;
	  break;

        case 'q':
	  quiet = 1;
	  break;

	case '?':
	default:
	  printf("ssh-keygen version %s\n", SSH_VERSION);
	  printf("Usage: %s [-b bits] [-p] [-c] [-f file] [-P pass] [-N new-pass] [-C comment]\n", av[0]);
	  exit(1);
	}
    }
  if (optind < ac)
    {
      printf("Too many arguments.\n");
      exit(1);
    }
  if (change_passphrase && change_comment)
    {
      printf("Can only have one of -p and -c.\n");
      exit(1);
    }

  /* If the user requested to change the passphrase, do it now.  This
     function never returns. */
  if (change_passphrase)
    do_change_passphrase(pw);

  /* If the user requested to change the comment, do it now.  This function
     never returns. */
  if (change_comment)
    do_change_comment(pw);

  arc4random_stir();

  if (quiet)
    rsa_set_verbose(0);

  /* Generate the rsa key pair. */
  private_key = RSA_new();
  public_key = RSA_new();
  rsa_generate_key(private_key, public_key, bits);

 ask_file_again:

  /* Ask for a file to save the key in. */
  if (identity_file)
    {
      strncpy(buf, identity_file, sizeof(buf));
      buf[sizeof(buf) - 1] = '\0';
    }
  else
    {
      printf("Enter file in which to save the key ($HOME/%s): ", 
	     SSH_CLIENT_IDENTITY);
      fflush(stdout);
      if (fgets(buf, sizeof(buf), stdin) == NULL)
	exit(1);
      if (strchr(buf, '\n'))
	*strchr(buf, '\n') = 0;
      if (strcmp(buf, "") == 0)
	snprintf(buf, sizeof buf, "%s/%s", pw->pw_dir, SSH_CLIENT_IDENTITY);
    }

  /* If the file aready exists, ask the user to confirm. */
  if (stat(buf, &st) >= 0)
    {
      printf("%s already exists.\n", buf);
      printf("Overwrite (y/n)? ");
      fflush(stdout);
      if (fgets(buf2, sizeof(buf2), stdin) == NULL)
	exit(1);
      if (buf2[0] != 'y' && buf2[0] != 'Y')
	exit(1);
    }
  
  /* Ask for a passphrase (twice). */
  if (identity_passphrase)
    passphrase1 = xstrdup(identity_passphrase);
  else
    if (identity_new_passphrase)
      passphrase1 = xstrdup(identity_new_passphrase);
    else
      {
      passphrase_again:
	passphrase1 = 
	  read_passphrase("Enter passphrase (empty for no passphrase): ", 1);
	passphrase2 = read_passphrase("Enter same passphrase again: ", 1);
	if (strcmp(passphrase1, passphrase2) != 0)
	  {
	    /* The passphrases do not match.  Clear them and retry. */
	    memset(passphrase1, 0, strlen(passphrase1));
	    memset(passphrase2, 0, strlen(passphrase2));
	    xfree(passphrase1);
	    xfree(passphrase2);
	    printf("Passphrases do not match.  Try again.\n");
	    goto passphrase_again;
	  }
	/* Clear the other copy of the passphrase. */
	memset(passphrase2, 0, strlen(passphrase2));
	xfree(passphrase2);
      }

  /* Create default commend field for the passphrase.  The user can later
     edit this field. */
  if (identity_comment)
    {
      strlcpy(buf2, identity_comment, sizeof(buf2));
    }
  else
    {
      if (gethostname(hostname, sizeof(hostname)) < 0)
	{
	  perror("gethostname");
	  exit(1);
	}
      snprintf(buf2, sizeof buf2, "%s@%s", pw->pw_name, hostname);
    }

  /* Save the key with the given passphrase and comment. */
  if (!save_private_key(buf, passphrase1, private_key, buf2))
    {
      printf("Saving the key failed: %s: %s.\n",
	     buf, strerror(errno));
      memset(passphrase1, 0, strlen(passphrase1));
      xfree(passphrase1);
      goto ask_file_again;
    }
  /* Clear the passphrase. */
  memset(passphrase1, 0, strlen(passphrase1));
  xfree(passphrase1);

  /* Clear the private key and the random number generator. */
  RSA_free(private_key);
  arc4random_stir();

  if (!quiet)
    printf("Your identification has been saved in %s.\n", buf);

  /* Display the public key on the screen. */
  if (!quiet) {
    printf("Your public key is:\n");
    printf("%d ", BN_num_bits(public_key->n));
    tmpbuf = BN_bn2dec(public_key->e);
    printf("%s ", tmpbuf);
    free(tmpbuf);
    tmpbuf = BN_bn2dec(public_key->n);
    printf("%s %s\n", tmpbuf, buf2);
    free(tmpbuf);
  }

  /* Save the public key in text format in a file with the same name but
     .pub appended. */
  strcat(buf, ".pub");
  f = fopen(buf, "w");
  if (!f)
    {
      printf("Could not save your public key in %s\n", buf);
      exit(1);
    }
  fprintf(f, "%d ", BN_num_bits(public_key->n));
  tmpbuf = BN_bn2dec(public_key->e);
  fprintf(f, "%s ", tmpbuf);
  free(tmpbuf);
  tmpbuf = BN_bn2dec(public_key->n);
  fprintf(f, "%s %s\n", tmpbuf, buf2);
  free(tmpbuf);
  fclose(f);

  if (!quiet)
    printf("Your public key has been saved in %s\n", buf);
  
  exit(0);
}
