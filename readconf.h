/*

readconf.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sat Apr 22 00:25:29 1995 ylo

Functions for reading the configuration file.

*/

/* RCSID("$Id: readconf.h,v 1.1 1999/10/27 03:42:44 damien Exp $"); */

#ifndef READCONF_H
#define READCONF_H

/* Data structure for representing a forwarding request. */

typedef struct
{
  int port;		/* Port to forward. */
  char *host;		/* Host to connect. */
  int host_port;	/* Port to connect on host. */
} Forward;

/* Data structure for representing option data. */

typedef struct
{
  int forward_agent;		/* Forward authentication agent. */
  int forward_x11;		/* Forward X11 display. */
  int gateway_ports;		/* Allow remote connects to forwarded ports. */
  int use_privileged_port;	/* Don't use privileged port if false. */
  int rhosts_authentication;	/* Try rhosts authentication. */
  int rhosts_rsa_authentication;/* Try rhosts with RSA authentication. */
  int rsa_authentication;	/* Try RSA authentication. */
#ifdef KRB4
  int kerberos_authentication;	/* Try Kerberos authentication. */
#endif
#ifdef AFS
  int kerberos_tgt_passing;	/* Try Kerberos tgt passing. */
  int afs_token_passing;	/* Try AFS token passing. */
#endif
  int password_authentication;	/* Try password authentication. */
  int fallback_to_rsh;		/* Use rsh if cannot connect with ssh. */
  int use_rsh;			/* Always use rsh (don\'t try ssh). */
  int batch_mode;		/* Batch mode: do not ask for passwords. */
  int check_host_ip;		/* Also keep track of keys for IP address */
  int strict_host_key_checking;	/* Strict host key checking. */
  int compression;		/* Compress packets in both directions. */
  int compression_level;	/* Compression level 1 (fast) to 9 (best). */
  int keepalives;		/* Set SO_KEEPALIVE. */

  int port;			/* Port to connect. */
  int connection_attempts;	/* Max attempts (seconds) before giving up */
  int number_of_password_prompts; /* Max number of password prompts. */
  int cipher;			/* Cipher to use. */
  char *hostname;		/* Real host to connect. */
  char *proxy_command;		/* Proxy command for connecting the host. */
  char *user;			/* User to log in as. */
  int escape_char;		/* Escape character; -2 = none */

  char *system_hostfile;	/* Path for /etc/ssh_known_hosts. */
  char *user_hostfile;		/* Path for $HOME/.ssh/known_hosts. */

  int num_identity_files;	/* Number of files for RSA identities. */
  char *identity_files[SSH_MAX_IDENTITY_FILES];

  /* Local TCP/IP forward requests. */
  int num_local_forwards;
  Forward local_forwards[SSH_MAX_FORWARDS_PER_DIRECTION];

  /* Remote TCP/IP forward requests. */
  int num_remote_forwards;
  Forward remote_forwards[SSH_MAX_FORWARDS_PER_DIRECTION];
} Options;


/* Initializes options to special values that indicate that they have not
   yet been set.  Read_config_file will only set options with this value.
   Options are processed in the following order: command line, user config
   file, system config file.  Last, fill_default_options is called. */
void initialize_options(Options *options);

/* Called after processing other sources of option data, this fills those
   options for which no value has been specified with their default values. */
void fill_default_options(Options *options);

/* Processes a single option line as used in the configuration files. 
   This only sets those values that have not already been set. */
void process_config_line(Options *options, const char *host,
			 char *line, const char *filename, int linenum,
			 int *activep);

/* Reads the config file and modifies the options accordingly.  Options should
   already be initialized before this call.  This never returns if there
   is an error.  If the file does not exist, this returns immediately. */
void read_config_file(const char *filename, const char *host, 
		      Options *options);

/* Adds a local TCP/IP port forward to options.  Never returns if there
   is an error. */
void add_local_forward(Options *options, int port, const char *host,
		       int host_port);

/* Adds a remote TCP/IP port forward to options.  Never returns if there
   is an error. */
void add_remote_forward(Options *options, int port, const char *host,
			int host_port);


#endif /* READCONF_H */
