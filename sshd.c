/*

sshd.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Fri Mar 17 17:09:28 1995 ylo

This program is the ssh daemon.  It listens for connections from clients, and
performs authentication, executes use commands or shell, and forwards
information to/from the application to the user client over an encrypted
connection.  This can also handle forwarding of X11, TCP/IP, and authentication
agent connections.

*/

#include "includes.h"
RCSID("$Id: sshd.c,v 1.1 1999/10/27 03:42:46 damien Exp $");

#include "xmalloc.h"
#include "rsa.h"
#include "ssh.h"
#include "pty.h"
#include "packet.h"
#include "buffer.h"
#include "cipher.h"
#include "mpaux.h"
#include "servconf.h"
#include "uidswap.h"
#include "compat.h"

#ifdef LIBWRAP
#include <tcpd.h>
#include <syslog.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
#endif /* LIBWRAP */

#ifndef O_NOCTTY
#define O_NOCTTY	0
#endif

#ifdef KRB4
char *ticket = NULL;
#endif /* KRB4 */

#ifdef HAVE_PAM
#include <security/pam_appl.h>
struct pam_handle_t *pamh=NULL;
char *pampasswd=NULL;
int retval;
int origretval;
#endif /* HAVE_PAM */

/* Local Xauthority file. */
char *xauthfile = NULL;

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
char *config_file_name = SERVER_CONFIG_FILE;

/* Debug mode flag.  This can be set on the command line.  If debug
   mode is enabled, extra debugging output will be sent to the system
   log, the daemon will not go to background, and will exit after processing
   the first connection. */
int debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
int inetd_flag = 0;

/* argv[0] without path. */
char *av0;

/* Saved arguments to main(). */
char **saved_argv;

/* This is set to the socket that the server is listening; this is used in
   the SIGHUP signal handler. */
int listen_sock;

/* Flags set in auth-rsa from authorized_keys flags.  These are set in
  auth-rsa.c. */
int no_port_forwarding_flag = 0;
int no_agent_forwarding_flag = 0;
int no_x11_forwarding_flag = 0;
int no_pty_flag = 0;
char *forced_command = NULL;  /* RSA authentication "command=" option. */
struct envstring *custom_environment = NULL; 
			  /* RSA authentication "environment=" options. */

/* Session id for the current session. */
unsigned char session_id[16];

/* Any really sensitive data in the application is contained in this structure.
   The idea is that this structure could be locked into memory so that the
   pages do not get written into swap.  However, there are some problems.
   The private key contains BIGNUMs, and we do not (in principle) have
   access to the internals of them, and locking just the structure is not
   very useful.  Currently, memory locking is not implemented. */
struct
{
  /* Private part of server key. */
  RSA *private_key;

  /* Private part of host key. */
  RSA *host_key;
} sensitive_data;

/* Flag indicating whether the current session key has been used.  This flag
   is set whenever the key is used, and cleared when the key is regenerated. */
int key_used = 0;

/* This is set to true when SIGHUP is received. */
int received_sighup = 0;

/* Public side of the server key.  This value is regenerated regularly with
   the private key. */
RSA *public_key;

/* Prototypes for various functions defined later in this file. */
void do_connection(int privileged_port);
void do_authentication(char *user, int privileged_port);
void do_authenticated(struct passwd *pw);
void do_exec_pty(const char *command, int ptyfd, int ttyfd, 
		 const char *ttyname, struct passwd *pw, const char *term,
		 const char *display, const char *auth_proto,
		 const char *auth_data);
void do_exec_no_pty(const char *command, struct passwd *pw,
		    const char *display, const char *auth_proto,
		    const char *auth_data);
void do_child(const char *command, struct passwd *pw, const char *term,
	      const char *display, const char *auth_proto,
	      const char *auth_data, const char *ttyname);
#ifdef HAVE_PAM
static int pamconv(int num_msg, const struct pam_message **msg,
                   struct pam_response **resp, void *appdata_ptr);

static struct pam_conv conv = {
    pamconv,
    NULL
};

static int pamconv(int num_msg, const struct pam_message **msg,
                   struct pam_response **resp, void *appdata_ptr)
{
  int count = 0;
  int replies = 0;
  struct pam_response *reply = NULL;
  int size = sizeof(struct pam_response);

  for(count = 0; count < num_msg; count++)
  {
    switch (msg[count]->msg_style)
    {
      case PAM_PROMPT_ECHO_ON:
      case PAM_PROMPT_ECHO_OFF:
        if (reply == NULL) 
          reply = xmalloc(size); 
        else 
          reply = realloc(reply, size);
			 
		  if (reply == NULL)
          return PAM_CONV_ERR; 
			 
        size += sizeof(struct pam_response);
		  
		  reply[replies].resp_retcode = PAM_SUCCESS;
		  
		  reply[replies++].resp = xstrdup(pampasswd);
			 /* PAM frees resp */
		  break;

		case PAM_TEXT_INFO:
		  /* ignore it... */
		  break;

		case PAM_ERROR_MSG:
		default:
		  /* Must be an error of some sort... */
		  if (reply != NULL)
          free(reply);

		  return PAM_CONV_ERR;
	 }
  }

  if (reply != NULL)
    *resp = reply;
	 
  return PAM_SUCCESS;
}

void pam_cleanup_proc(void *context)
{
  if (retval == PAM_SUCCESS) 
    retval = pam_close_session((pam_handle_t *)pamh, 0);
	 
  if (pam_end((pam_handle_t *)pamh, retval) != PAM_SUCCESS)
    log("Cannot release PAM authentication.");
}
#endif /* HAVE_PAM */

/* Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
   the effect is to reread the configuration file (and to regenerate
   the server key). */

void sighup_handler(int sig)
{
  received_sighup = 1;
  signal(SIGHUP, sighup_handler);
}

/* Called from the main program after receiving SIGHUP.  Restarts the 
   server. */

void sighup_restart()
{
  log("Received SIGHUP; restarting.");
  close(listen_sock);
  execv(saved_argv[0], saved_argv);
  log("RESTART FAILED: av0='%s', error: %s.", av0, strerror(errno));
  exit(1);
}

/* Generic signal handler for terminating signals in the master daemon. 
   These close the listen socket; not closing it seems to cause "Address
   already in use" problems on some machines, which is inconvenient. */

void sigterm_handler(int sig)
{
  log("Received signal %d; terminating.", sig);
  close(listen_sock);
  exit(255);
}

/* SIGCHLD handler.  This is called whenever a child dies.  This will then 
   reap any zombies left by exited c. */

void main_sigchld_handler(int sig)
{
  int save_errno = errno;
  int status;
  wait(&status);
  signal(SIGCHLD, main_sigchld_handler);
  errno = save_errno;
}

/* Signal handler for the alarm after the login grace period has expired. */

void grace_alarm_handler(int sig)
{
  /* Close the connection. */
  packet_close();
  
  /* Log error and exit. */
  fatal("Timeout before authentication.");
}

/* Signal handler for the key regeneration alarm.  Note that this
   alarm only occurs in the daemon waiting for connections, and it does not
   do anything with the private key or random state before forking.  Thus there
   should be no concurrency control/asynchronous execution problems. */

void key_regeneration_alarm(int sig)
{
  int save_errno = errno;

  /* Check if we should generate a new key. */
  if (key_used)
    {
      /* This should really be done in the background. */
      log("Generating new %d bit RSA key.", options.server_key_bits);

      if (sensitive_data.private_key != NULL)
	RSA_free(sensitive_data.private_key);
      sensitive_data.private_key = RSA_new();

      if (public_key != NULL) 
	RSA_free(public_key);
      public_key = RSA_new();

      rsa_generate_key(sensitive_data.private_key, public_key, 
		       options.server_key_bits);
      arc4random_stir();
      key_used = 0;
      log("RSA key generation complete.");
    }

  /* Reschedule the alarm. */
  signal(SIGALRM, key_regeneration_alarm);
  alarm(options.key_regeneration_time);
  errno = save_errno;
}

/* Main program for the daemon. */

int
main(int ac, char **av)
{
  extern char *optarg;
  extern int optind;
  int opt, aux, sock_in, sock_out, newsock, i, pid, on = 1;
  int remote_major, remote_minor;
  int silentrsa = 0;
  struct sockaddr_in sin;
  char buf[100]; /* Must not be larger than remote_version. */
  char remote_version[100]; /* Must be at least as big as buf. */
  char *comment;
  FILE *f;
  struct linger linger;

  /* Save argv[0]. */
  saved_argv = av;
  if (strchr(av[0], '/'))
    av0 = strrchr(av[0], '/') + 1;
  else
    av0 = av[0];

  /* Initialize configuration options to their default values. */
  initialize_server_options(&options);

  /* Parse command-line arguments. */
  while ((opt = getopt(ac, av, "f:p:b:k:h:g:diqQ")) != EOF)
    {
      switch (opt)
	{
	case 'f':
	  config_file_name = optarg;
	  break;
	case 'd':
	  debug_flag = 1;
	  break;
	case 'i':
	  inetd_flag = 1;
	  break;
	case 'Q':
          silentrsa = 1;
	  break;
	case 'q':
	  options.quiet_mode = 1;
	  break;
	case 'b':
	  options.server_key_bits = atoi(optarg);
	  break;
	case 'p':
	  options.port = atoi(optarg);
	  break;
	case 'g':
	  options.login_grace_time = atoi(optarg);
	  break;
	case 'k':
	  options.key_regeneration_time = atoi(optarg);
	  break;
	case 'h':
	  options.host_key_file = optarg;
	  break;
	case '?':
	default:
	  fprintf(stderr, "sshd version %s\n", SSH_VERSION);
	  fprintf(stderr, "Usage: %s [options]\n", av0);
	  fprintf(stderr, "Options:\n");
	  fprintf(stderr, "  -f file    Configuration file (default %s/sshd_config)\n", ETCDIR);
	  fprintf(stderr, "  -d         Debugging mode\n");
	  fprintf(stderr, "  -i         Started from inetd\n");
	  fprintf(stderr, "  -q         Quiet (no logging)\n");
	  fprintf(stderr, "  -p port    Listen on the specified port (default: 22)\n");
	  fprintf(stderr, "  -k seconds Regenerate server key every this many seconds (default: 3600)\n");
	  fprintf(stderr, "  -g seconds Grace period for authentication (default: 300)\n");
	  fprintf(stderr, "  -b bits    Size of server RSA key (default: 768 bits)\n");
	  fprintf(stderr, "  -h file    File from which to read host key (default: %s)\n",
		  HOST_KEY_FILE);
	  exit(1);
	}
    }

  /* check if RSA support exists */
  if (rsa_alive() == 0) {
    if (silentrsa == 0)
      printf("sshd: no RSA support in libssl and libcrypto -- exiting.  See ssl(8)\n");
    log("no RSA support in libssl and libcrypto -- exiting.  See ssl(8)");
    exit(1);
  }

  /* Read server configuration options from the configuration file. */
  read_server_config(&options, config_file_name);

  /* Fill in default values for those options not explicitly set. */
  fill_default_server_options(&options);

  /* Check certain values for sanity. */
  if (options.server_key_bits < 512 || 
      options.server_key_bits > 32768)
    {
      fprintf(stderr, "Bad server key size.\n");
      exit(1);
    }
  if (options.port < 1 || options.port > 65535)
    {
      fprintf(stderr, "Bad port number.\n");
      exit(1);
    }

  /* Check that there are no remaining arguments. */
  if (optind < ac)
    {
      fprintf(stderr, "Extra argument %s.\n", av[optind]);
      exit(1);
    }

  /* Initialize the log (it is reinitialized below in case we forked). */
  log_init(av0, debug_flag && !inetd_flag, 
	   debug_flag || options.fascist_logging, 
	   options.quiet_mode, options.log_facility);

  debug("sshd version %.100s", SSH_VERSION);

  sensitive_data.host_key = RSA_new();
  /* Load the host key.  It must have empty passphrase. */
  if (!load_private_key(options.host_key_file, "", 
			sensitive_data.host_key, &comment))
    {
      if (debug_flag)
	fprintf(stderr, "Could not load host key: %s: %s\n",
		options.host_key_file, strerror(errno));
      else
	{
	  int err = errno;
	  log_init(av0, !inetd_flag, 1, 0, options.log_facility);
	  error("Could not load host key: %.200s: %.100s", 
		options.host_key_file, strerror(err));
	}
      exit(1);
    }
  xfree(comment);

  /* If not in debugging mode, and not started from inetd, disconnect from
     the controlling terminal, and fork.  The original process exits. */
  if (!debug_flag && !inetd_flag)
    { 
#ifdef TIOCNOTTY
      int fd;
#endif /* TIOCNOTTY */
      if (daemon(0, 0) < 0)
	  fatal("daemon() failed: %.200s", strerror(errno));
     
      /* Disconnect from the controlling tty. */
#ifdef TIOCNOTTY
      fd = open("/dev/tty", O_RDWR|O_NOCTTY);
      if (fd >= 0)
	{
	  (void)ioctl(fd, TIOCNOTTY, NULL);
	  close(fd);
	}
#endif /* TIOCNOTTY */
    }

  /* Reinitialize the log (because of the fork above). */
  log_init(av0, debug_flag && !inetd_flag, 
	   debug_flag || options.fascist_logging, 
	   options.quiet_mode, options.log_facility);

  /* Check that server and host key lengths differ sufficiently.  This is
     necessary to make double encryption work with rsaref.  Oh, I hate
     software patents. I dont know if this can go? Niels */
  if (options.server_key_bits > 
      BN_num_bits(sensitive_data.host_key->n) - SSH_KEY_BITS_RESERVED &&
      options.server_key_bits < 
      BN_num_bits(sensitive_data.host_key->n) + SSH_KEY_BITS_RESERVED)
    {
      options.server_key_bits = 
	BN_num_bits(sensitive_data.host_key->n) + SSH_KEY_BITS_RESERVED;
      debug("Forcing server key to %d bits to make it differ from host key.", 
	    options.server_key_bits);
    }

  /* Do not display messages to stdout in RSA code. */
  rsa_set_verbose(0);

  /* Initialize the random number generator. */
  arc4random_stir();
  
  /* Chdir to the root directory so that the current disk can be unmounted
     if desired. */
  chdir("/");
  
  /* Close connection cleanly after attack. */
  cipher_attack_detected = packet_disconnect;

  /* Start listening for a socket, unless started from inetd. */
  if (inetd_flag)
    {
      int s1, s2;
      s1 = dup(0);  /* Make sure descriptors 0, 1, and 2 are in use. */
      s2 = dup(s1);
      sock_in = dup(0);
      sock_out = dup(1);
      /* We intentionally do not close the descriptors 0, 1, and 2 as our
	 code for setting the descriptors won\'t work if ttyfd happens to
	 be one of those. */
      debug("inetd sockets after dupping: %d, %d", sock_in, sock_out);

      public_key = RSA_new();
      sensitive_data.private_key = RSA_new();
      /* Generate an rsa key. */
      log("Generating %d bit RSA key.", options.server_key_bits);
      rsa_generate_key(sensitive_data.private_key, public_key,
		       options.server_key_bits);
      arc4random_stir();
      log("RSA key generation complete.");
    }
  else
    {
      /* Create socket for listening. */
      listen_sock = socket(AF_INET, SOCK_STREAM, 0);
      if (listen_sock < 0)
	fatal("socket: %.100s", strerror(errno));

      /* Set socket options.  We try to make the port reusable and have it
	 close as fast as possible without waiting in unnecessary wait states
	 on close. */
      setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (void *)&on, 
		 sizeof(on));
      linger.l_onoff = 1;
      linger.l_linger = 5;
      setsockopt(listen_sock, SOL_SOCKET, SO_LINGER, (void *)&linger, 
		 sizeof(linger));

      /* Initialize the socket address. */
      memset(&sin, 0, sizeof(sin));
      sin.sin_family = AF_INET;
      sin.sin_addr = options.listen_addr;
      sin.sin_port = htons(options.port);

      /* Bind the socket to the desired port. */
      if (bind(listen_sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
	  error("bind: %.100s", strerror(errno));
	  shutdown(listen_sock, SHUT_RDWR);
	  close(listen_sock);
	  fatal("Bind to port %d failed.", options.port);
	}

      if (!debug_flag)
	{
	  /* Record our pid in /etc/sshd_pid to make it easier to kill the
	     correct sshd.  We don\'t want to do this before the bind above
	     because the bind will fail if there already is a daemon, and this
	     will overwrite any old pid in the file. */
	  f = fopen(SSH_DAEMON_PID_FILE, "w");
	  if (f)
	    {
	      fprintf(f, "%u\n", (unsigned int)getpid());
	      fclose(f);
	    }
	}

      /* Start listening on the port. */
      log("Server listening on port %d.", options.port);
      if (listen(listen_sock, 5) < 0)
	fatal("listen: %.100s", strerror(errno));

      public_key = RSA_new();
      sensitive_data.private_key = RSA_new();
      /* Generate an rsa key. */
      log("Generating %d bit RSA key.", options.server_key_bits);
      rsa_generate_key(sensitive_data.private_key, public_key,
		       options.server_key_bits);
      arc4random_stir();
      log("RSA key generation complete.");

      /* Schedule server key regeneration alarm. */
      signal(SIGALRM, key_regeneration_alarm);
      alarm(options.key_regeneration_time);

      /* Arrange to restart on SIGHUP.  The handler needs listen_sock. */
      signal(SIGHUP, sighup_handler);
      signal(SIGTERM, sigterm_handler);
      signal(SIGQUIT, sigterm_handler);
      
      /* Arrange SIGCHLD to be caught. */
      signal(SIGCHLD, main_sigchld_handler);

      /* Stay listening for connections until the system crashes or the
	 daemon is killed with a signal. */
      for (;;)
	{
	  if (received_sighup)
	    sighup_restart();
	  /* Wait in accept until there is a connection. */
	  aux = sizeof(sin);
	  newsock = accept(listen_sock, (struct sockaddr *)&sin, &aux);
	  if (received_sighup)
	    sighup_restart();
	  if (newsock < 0)
	    {
	      if (errno == EINTR)
		continue;
	      error("accept: %.100s", strerror(errno));
	      continue;
	    }

	  /* Got connection.  Fork a child to handle it, unless we are in
	     debugging mode. */
	  if (debug_flag)
	    {
	      /* In debugging mode.  Close the listening socket, and start
		 processing the connection without forking. */
	      debug("Server will not fork when running in debugging mode.");
	      close(listen_sock);
	      sock_in = newsock;
	      sock_out = newsock;
	      pid = getpid();
	      break;
	    }
	  else
	    {
	      /* Normal production daemon.  Fork, and have the child process
		 the connection.  The parent continues listening. */
	      if ((pid = fork()) == 0)
		{ 
		  /* Child.  Close the listening socket, and start using
		     the accepted socket.  Reinitialize logging (since our
		     pid has changed).  We break out of the loop to handle
		     the connection. */
		  close(listen_sock);
		  sock_in = newsock;
		  sock_out = newsock;
		  log_init(av0, debug_flag && !inetd_flag, 
			   options.fascist_logging || debug_flag, 
			   options.quiet_mode, options.log_facility);
		  break;
		}
	    }

	  /* Parent.  Stay in the loop. */
	  if (pid < 0)
	    error("fork: %.100s", strerror(errno));
	  else
	    debug("Forked child %d.", pid);

	  /* Mark that the key has been used (it was "given" to the child). */
	  key_used = 1;

	  arc4random_stir();

	  /* Close the new socket (the child is now taking care of it). */
	  close(newsock);
	}
    }
  
  /* This is the child processing a new connection. */

  /* Disable the key regeneration alarm.  We will not regenerate the key
     since we are no longer in a position to give it to anyone.  We will
     not restart on SIGHUP since it no longer makes sense. */
  alarm(0);
  signal(SIGALRM, SIG_DFL);
  signal(SIGHUP, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
  signal(SIGQUIT, SIG_DFL);
  signal(SIGCHLD, SIG_DFL);

  /* Set socket options for the connection.  We want the socket to close
     as fast as possible without waiting for anything.  If the connection
     is not a socket, these will do nothing. */
  /* setsockopt(sock_in, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)); */
  linger.l_onoff = 1;
  linger.l_linger = 5;
  setsockopt(sock_in, SOL_SOCKET, SO_LINGER, (void *)&linger, sizeof(linger));

  /* Register our connection.  This turns encryption off because we do not
     have a key. */
  packet_set_connection(sock_in, sock_out);

  /* Check whether logins are denied from this host. */
#ifdef LIBWRAP
  {
    struct request_info req;

    request_init(&req, RQ_DAEMON, av0, RQ_FILE, sock_in, NULL);
    fromhost(&req);

    if (!hosts_access(&req)) {
      close(sock_in);
      close(sock_out);
      refuse(&req);
    }
    log("Connection from %.500s port %d",
	eval_client(&req), get_remote_port());
  }
#else
  /* Log the connection. */
  log("Connection from %.100s port %d", 
      get_remote_ipaddr(), get_remote_port());
#endif /* LIBWRAP */

  /* We don\'t want to listen forever unless the other side successfully
     authenticates itself.  So we set up an alarm which is cleared after
     successful authentication.  A limit of zero indicates no limit.
     Note that we don\'t set the alarm in debugging mode; it is just annoying
     to have the server exit just when you are about to discover the bug. */
  signal(SIGALRM, grace_alarm_handler);
  if (!debug_flag)
    alarm(options.login_grace_time);

  /* Send our protocol version identification. */
  snprintf(buf, sizeof buf, "SSH-%d.%d-%.100s\n", 
	  PROTOCOL_MAJOR, PROTOCOL_MINOR, SSH_VERSION);
  if (write(sock_out, buf, strlen(buf)) != strlen(buf))
    fatal("Could not write ident string.");

  /* Read other side\'s version identification. */
  for (i = 0; i < sizeof(buf) - 1; i++)
    {
      if (read(sock_in, &buf[i], 1) != 1)
	fatal("Did not receive ident string.");
      if (buf[i] == '\r')
	{
	  buf[i] = '\n';
	  buf[i + 1] = 0;
	  break;
	}
      if (buf[i] == '\n')
	{
	  /* buf[i] == '\n' */
	  buf[i + 1] = 0;
	  break;
	}
    }
  buf[sizeof(buf) - 1] = 0;
  
  /* Check that the versions match.  In future this might accept several
     versions and set appropriate flags to handle them. */
  if (sscanf(buf, "SSH-%d.%d-%[^\n]\n", &remote_major, &remote_minor, 
	     remote_version) != 3)
    {
      const char *s = "Protocol mismatch.\n";
      (void) write(sock_out, s, strlen(s));
      close(sock_in);
      close(sock_out);
      fatal("Bad protocol version identification: %.100s", buf);
    }
  debug("Client protocol version %d.%d; client software version %.100s",
	remote_major, remote_minor, remote_version);
  if (remote_major != PROTOCOL_MAJOR)
    {
      const char *s = "Protocol major versions differ.\n";
      (void) write(sock_out, s, strlen(s));
      close(sock_in);
      close(sock_out);
      fatal("Protocol major versions differ: %d vs. %d", 
	    PROTOCOL_MAJOR, remote_major);
    }

  /* Check that the client has sufficiently high software version. */
  if (remote_major == 1 && remote_minor < 3)
    packet_disconnect("Your ssh version is too old and is no longer supported.  Please install a newer version.");

  if (remote_major == 1 && remote_minor == 3) {
    enable_compat13();
    if (strcmp(remote_version, "OpenSSH-1.1") != 0) {
        debug("Agent forwarding disabled, remote version is not compatible.");
        no_agent_forwarding_flag = 1;
    }
  }

  packet_set_nonblocking();
  
  /* Handle the connection.   We pass as argument whether the connection
     came from a privileged port. */
  do_connection(get_remote_port() < IPPORT_RESERVED);

#ifdef KRB4
  /* Cleanup user's ticket cache file. */
  if (options.kerberos_ticket_cleanup)
    (void) dest_tkt();
#endif /* KRB4 */

  /* Cleanup user's local Xauthority file. */
  if (xauthfile) unlink(xauthfile);

  /* The connection has been terminated. */
  log("Closing connection to %.100s", inet_ntoa(sin.sin_addr));

#ifdef HAVE_PAM
  if (retval == PAM_SUCCESS)
    retval = pam_close_session((pam_handle_t *)pamh, 0);

  if (pam_end((pam_handle_t *)pamh, retval) != PAM_SUCCESS)
    log("Cannot release PAM authentication.");
	 
  fatal_remove_cleanup(&pam_cleanup_proc, NULL);
#endif /* HAVE_PAM */

  packet_close();

  exit(0);
}

/* Process an incoming connection.  Protocol version identifiers have already
   been exchanged.  This sends server key and performs the key exchange.
   Server and host keys will no longer be needed after this functions. */

void do_connection(int privileged_port)
{
  int i;
  BIGNUM *session_key_int;
  unsigned char session_key[SSH_SESSION_KEY_LENGTH];
  unsigned char check_bytes[8];
  char *user;
  unsigned int cipher_type, auth_mask, protocol_flags;
  int plen, slen;
  u_int32_t rand = 0;

  /* Generate check bytes that the client must send back in the user packet
     in order for it to be accepted; this is used to defy ip spoofing 
     attacks.  Note that this only works against somebody doing IP spoofing 
     from a remote machine; any machine on the local network can still see 
     outgoing packets and catch the random cookie.  This only affects
     rhosts authentication, and this is one of the reasons why it is
     inherently insecure. */
  for (i = 0; i < 8; i++) {
    if (i % 4 == 0)
      rand = arc4random();
    check_bytes[i] = rand & 0xff;
    rand >>= 8;
  }
  
  /* Send our public key.  We include in the packet 64 bits of random
     data that must be matched in the reply in order to prevent IP spoofing. */
  packet_start(SSH_SMSG_PUBLIC_KEY);
  for (i = 0; i < 8; i++)
    packet_put_char(check_bytes[i]);

  /* Store our public server RSA key. */
  packet_put_int(BN_num_bits(public_key->n));
  packet_put_bignum(public_key->e);
  packet_put_bignum(public_key->n);

  /* Store our public host RSA key. */
  packet_put_int(BN_num_bits(sensitive_data.host_key->n));
  packet_put_bignum(sensitive_data.host_key->e);
  packet_put_bignum(sensitive_data.host_key->n);

  /* Put protocol flags. */
  packet_put_int(SSH_PROTOFLAG_HOST_IN_FWD_OPEN);

  /* Declare which ciphers we support. */
  packet_put_int(cipher_mask());

  /* Declare supported authentication types. */
  auth_mask = 0;
  if (options.rhosts_authentication)
    auth_mask |= 1 << SSH_AUTH_RHOSTS;
  if (options.rhosts_rsa_authentication)
    auth_mask |= 1 << SSH_AUTH_RHOSTS_RSA;
  if (options.rsa_authentication)
    auth_mask |= 1 << SSH_AUTH_RSA;
#ifdef KRB4
  if (options.kerberos_authentication)
    auth_mask |= 1 << SSH_AUTH_KERBEROS;
#endif
#ifdef AFS
  if (options.kerberos_tgt_passing)
    auth_mask |= 1 << SSH_PASS_KERBEROS_TGT;
  if (options.afs_token_passing)
    auth_mask |= 1 << SSH_PASS_AFS_TOKEN;
#endif
  if (options.password_authentication)
    auth_mask |= 1 << SSH_AUTH_PASSWORD;
  packet_put_int(auth_mask);

  /* Send the packet and wait for it to be sent. */
  packet_send();
  packet_write_wait();

  debug("Sent %d bit public key and %d bit host key.", 
	BN_num_bits(public_key->n), BN_num_bits(sensitive_data.host_key->n));

  /* Read clients reply (cipher type and session key). */
  packet_read_expect(&plen, SSH_CMSG_SESSION_KEY);

  /* Get cipher type. */
  cipher_type = packet_get_char();

  /* Get check bytes from the packet.  These must match those we sent earlier
     with the public key packet. */
  for (i = 0; i < 8; i++)
    if (check_bytes[i] != packet_get_char())
      packet_disconnect("IP Spoofing check bytes do not match.");

  debug("Encryption type: %.200s", cipher_name(cipher_type));

  /* Get the encrypted integer. */
  session_key_int = BN_new();
  packet_get_bignum(session_key_int, &slen);

  /* Get protocol flags. */
  protocol_flags = packet_get_int();
  packet_set_protocol_flags(protocol_flags);

  packet_integrity_check(plen, 1 + 8 + slen + 4, SSH_CMSG_SESSION_KEY);

  /* Decrypt it using our private server key and private host key (key with 
     larger modulus first). */
  if (BN_cmp(sensitive_data.private_key->n, sensitive_data.host_key->n) > 0)
    {
      /* Private key has bigger modulus. */
      assert(BN_num_bits(sensitive_data.private_key->n) >= 
	     BN_num_bits(sensitive_data.host_key->n) + SSH_KEY_BITS_RESERVED);
      rsa_private_decrypt(session_key_int, session_key_int,
			  sensitive_data.private_key);
      rsa_private_decrypt(session_key_int, session_key_int,
			  sensitive_data.host_key);
    }
  else
    {
      /* Host key has bigger modulus (or they are equal). */
      assert(BN_num_bits(sensitive_data.host_key->n) >= 
	     BN_num_bits(sensitive_data.private_key->n) +
	     SSH_KEY_BITS_RESERVED);
      rsa_private_decrypt(session_key_int, session_key_int,
			  sensitive_data.host_key);
      rsa_private_decrypt(session_key_int, session_key_int,
			  sensitive_data.private_key);
    }

  /* Compute session id for this session. */
  compute_session_id(session_id, check_bytes,
		     BN_num_bits(sensitive_data.host_key->n),
		     sensitive_data.host_key->n, 
		     BN_num_bits(sensitive_data.private_key->n),
		     sensitive_data.private_key->n);

  /* Extract session key from the decrypted integer.  The key is in the 
     least significant 256 bits of the integer; the first byte of the 
     key is in the highest bits. */
  BN_mask_bits(session_key_int, sizeof(session_key) * 8);
  assert(BN_num_bytes(session_key_int) == sizeof(session_key));
  BN_bn2bin(session_key_int, session_key);
  
  /* Xor the first 16 bytes of the session key with the session id. */
  for (i = 0; i < 16; i++)
    session_key[i] ^= session_id[i];

  /* Destroy the decrypted integer.  It is no longer needed. */
  BN_clear_free(session_key_int);
  
  /* Set the session key.  From this on all communications will be
     encrypted. */
  packet_set_encryption_key(session_key, SSH_SESSION_KEY_LENGTH, 
			    cipher_type, 0);
  
  /* Destroy our copy of the session key.  It is no longer needed. */
  memset(session_key, 0, sizeof(session_key));

  debug("Received session key; encryption turned on.");

  /* Send an acknowledgement packet.  Note that this packet is sent
     encrypted. */
  packet_start(SSH_SMSG_SUCCESS);
  packet_send();
  packet_write_wait();

  /* Get the name of the user that we wish to log in as. */
  packet_read_expect(&plen, SSH_CMSG_USER);

  /* Get the user name. */
  {
    int ulen;
    user = packet_get_string(&ulen);
    packet_integrity_check(plen, (4 + ulen), SSH_CMSG_USER);
  }

  /* Destroy the private and public keys.  They will no longer be needed. */
  RSA_free(public_key);
  RSA_free(sensitive_data.private_key);
  RSA_free(sensitive_data.host_key);

  setproctitle("%s", user);
  /* Do the authentication. */
  do_authentication(user, privileged_port);
}

/* Check if the user is allowed to log in via ssh. If user is listed in
   DenyUsers or user's primary group is listed in DenyGroups, false will
   be returned. If AllowUsers isn't empty and user isn't listed there, or
   if AllowGroups isn't empty and user isn't listed there, false will be
   returned. Otherwise true is returned.
   XXX This function should also check if user has a valid shell */

static int
allowed_user(struct passwd *pw)
{
  struct group *grp;
  int i;

  /* Shouldn't be called if pw is NULL, but better safe than sorry... */
  if (!pw)
    return 0;

  /* XXX Should check for valid login shell */

  /* Return false if user is listed in DenyUsers */
  if (options.num_deny_users > 0)
    {
      if (!pw->pw_name)
	return 0;
      for (i = 0; i < options.num_deny_users; i++)
	if (match_pattern(pw->pw_name, options.deny_users[i]))
	  return 0;
    }

  /* Return false if AllowUsers isn't empty and user isn't listed there */
  if (options.num_allow_users > 0)
    {
      if (!pw->pw_name)
	return 0;
      for (i = 0; i < options.num_allow_users; i++)
	if (match_pattern(pw->pw_name, options.allow_users[i]))
	  break;
      /* i < options.num_allow_users iff we break for loop */
      if (i >= options.num_allow_users)
	return 0;
    }

  /* Get the primary group name if we need it. Return false if it fails */
  if (options.num_deny_groups > 0 || options.num_allow_groups > 0 )
    {
      grp = getgrgid(pw->pw_gid);
      if (!grp)
	return 0;

      /* Return false if user's group is listed in DenyGroups */
      if (options.num_deny_groups > 0)
        {
          if (!grp->gr_name)
	    return 0;
          for (i = 0; i < options.num_deny_groups; i++)
	    if (match_pattern(grp->gr_name, options.deny_groups[i]))
	      return 0;
        }

      /* Return false if AllowGroups isn't empty and user's group isn't
	 listed there */
      if (options.num_allow_groups > 0)
        {
          if (!grp->gr_name)
	    return 0;
          for (i = 0; i < options.num_allow_groups; i++)
	    if (match_pattern(grp->gr_name, options.allow_groups[i]))
	      break;
          /* i < options.num_allow_groups iff we break for loop */
          if (i >= options.num_allow_groups)
	    return 0;
        }
    }

  /* We found no reason not to let this user try to log on... */
  return 1;
}

/* Performs authentication of an incoming connection.  Session key has already
   been exchanged and encryption is enabled.  User is the user name to log
   in as (received from the clinet).  Privileged_port is true if the
   connection comes from a privileged port (used for .rhosts authentication).*/

#define MAX_AUTH_FAILURES 5

void
do_authentication(char *user, int privileged_port)
{
  int type;
  int authenticated = 0;
  int authentication_failures = 0;
  char *password;
  struct passwd *pw, pwcopy;
  char *client_user;
  unsigned int client_host_key_bits;
  BIGNUM *client_host_key_e, *client_host_key_n;
#ifdef HAVE_PAM
  int pam_auth_ok;
#endif /* HAVE_PAM */
			 
#ifdef AFS
  /* If machine has AFS, set process authentication group. */
  if (k_hasafs()) {
    k_setpag();
    k_unlog();
  }
#endif /* AFS */
       
  /* Verify that the user is a valid user. */
  pw = getpwnam(user);
#ifdef HAVE_PAM
  if ((pw != NULL) && allowed_user(pw))
  {
    /* Initialise PAM */
    retval = pam_start("ssh", pw->pw_name, &conv, (pam_handle_t **)&pamh);
    fatal_add_cleanup(&pam_cleanup_proc, NULL); 
    origretval = retval;
    if (retval == PAM_SUCCESS)
	 	pam_auth_ok = 1;
  }
  
  if (pam_auth_ok == 0)
#else /* HAVE_PAM */
  if (!pw || !allowed_user(pw))
#endif /* HAVE_PAM */
    {
      /* The user does not exist or access is denied,
         but fake indication that authentication is needed. */
      packet_start(SSH_SMSG_FAILURE);
      packet_send();
      packet_write_wait();

      /* Keep reading packets, and always respond with a failure.  This is to
	 avoid disclosing whether such a user really exists. */
      for (;;)
	{
	  /* Read a packet.  This will not return if the client disconnects. */
	  int plen;
	  int type = packet_read(&plen);
#ifdef SKEY
	  int passw_len;
	  char *password, *skeyinfo;
	  if (options.password_authentication &&
	     options.skey_authentication == 1 &&
	     type == SSH_CMSG_AUTH_PASSWORD &&
	     (password = packet_get_string(&passw_len)) != NULL &&
	     passw_len == 5 &&
	     strncasecmp(password, "s/key", 5) == 0 &&
	     (skeyinfo = skey_fake_keyinfo(user)) != NULL ){
	    /* Send a fake s/key challenge. */
	    packet_send_debug(skeyinfo);
          }
#endif
	  /* Send failure.  This should be indistinguishable from a failed
	     authentication. */
	  packet_start(SSH_SMSG_FAILURE);
	  packet_send();
	  packet_write_wait();
          if (++authentication_failures >= MAX_AUTH_FAILURES) {
	    packet_disconnect("Too many authentication failures for %.100s from %.200s", 
            		       user, get_canonical_hostname());
          }
	}
      /*NOTREACHED*/
      abort();
    }
  
  /* Take a copy of the returned structure. */
  memset(&pwcopy, 0, sizeof(pwcopy));
  pwcopy.pw_name = xstrdup(pw->pw_name);
  pwcopy.pw_passwd = xstrdup(pw->pw_passwd);
  pwcopy.pw_uid = pw->pw_uid;
  pwcopy.pw_gid = pw->pw_gid;
  pwcopy.pw_dir = xstrdup(pw->pw_dir);
  pwcopy.pw_shell = xstrdup(pw->pw_shell);
  pw = &pwcopy;

  /* If we are not running as root, the user must have the same uid as the
     server. */
  if (getuid() != 0 && pw->pw_uid != getuid())
    packet_disconnect("Cannot change user when server not running as root.");

  debug("Attempting authentication for %.100s.", user);

  /* If the user has no password, accept authentication immediately. */
  if (options.password_authentication &&
#ifdef KRB4
      (!options.kerberos_authentication || options.kerberos_or_local_passwd) &&
#endif /* KRB4 */
      auth_password(pw, ""))
    {
      /* Authentication with empty password succeeded. */
      debug("Login for user %.100s accepted without authentication.", user);
      /* authentication_type = SSH_AUTH_PASSWORD; */
      authenticated = 1;
      /* Success packet will be sent after loop below. */
    }
  else
    {
      /* Indicate that authentication is needed. */
      packet_start(SSH_SMSG_FAILURE);
      packet_send();
      packet_write_wait();
    }

  /* Loop until the user has been authenticated or the connection is closed. */
  while (!authenticated)
    {
      int plen;
      /* Get a packet from the client. */
      type = packet_read(&plen);
      
      /* Process the packet. */
      switch (type)
	{

#ifdef AFS
	case SSH_CMSG_HAVE_KERBEROS_TGT:
	  if (!options.kerberos_tgt_passing)
	    {
	      /* packet_get_all(); */
	      log("Kerberos tgt passing disabled.");
	      break;
	    }
	  else {
	    /* Accept Kerberos tgt. */
	    int dlen;
	    char *tgt = packet_get_string(&dlen);
	    packet_integrity_check(plen, 4 + dlen, type);
	    if (!auth_kerberos_tgt(pw, tgt))
	      debug("Kerberos tgt REFUSED for %s", user);
	    xfree(tgt);
	  }
	  continue;

	case SSH_CMSG_HAVE_AFS_TOKEN:
	  if (!options.afs_token_passing || !k_hasafs()) {
	    /* packet_get_all(); */
	    log("AFS token passing disabled.");
	    break;
	  }
	  else {
	    /* Accept AFS token. */
	    int dlen;
	    char *token_string = packet_get_string(&dlen);
	    packet_integrity_check(plen, 4 + dlen, type);
	    if (!auth_afs_token(user, pw->pw_uid, token_string))
	      debug("AFS token REFUSED for %s", user);
	    xfree(token_string);
	    continue;
	  }
#endif /* AFS */
	  
#ifdef KRB4
	case SSH_CMSG_AUTH_KERBEROS:
	  if (!options.kerberos_authentication)
	    {
	      /* packet_get_all(); */
	      log("Kerberos authentication disabled.");
	      break;
	    }
	  else {
	    /* Try Kerberos v4 authentication. */
	    KTEXT_ST auth;
	    char *tkt_user = NULL;
	    char *kdata = packet_get_string((unsigned int *)&auth.length);
	    packet_integrity_check(plen, 4 + auth.length, type);

	    if (auth.length < MAX_KTXT_LEN)
	      memcpy(auth.dat, kdata, auth.length);
	    xfree(kdata);
	    
	    if (auth_krb4(user, &auth, &tkt_user)) {
	      /* Client has successfully authenticated to us. */
	      log("Kerberos authentication accepted %s for account "
		  "%s from %s", tkt_user, user, get_canonical_hostname());
	      /* authentication_type = SSH_AUTH_KERBEROS; */
	      authenticated = 1;
	      xfree(tkt_user);
	    }
	    else {
	      log("Kerberos authentication failed for account "
		  "%s from %s", user, get_canonical_hostname());
	    }
	  }
	  break;
#endif /* KRB4 */
	  
	case SSH_CMSG_AUTH_RHOSTS:
	  if (!options.rhosts_authentication)
	    {
	      log("Rhosts authentication disabled.");
	      break;
	    }

	  /* Rhosts authentication (also uses /etc/hosts.equiv). */
	  if (!privileged_port)
	    {
	      log("Rhosts authentication not available for connections from unprivileged port.");
	      break;
	    }

	  /* Get client user name.  Note that we just have to trust the client;
	     this is one reason why rhosts authentication is insecure. 
	     (Another is IP-spoofing on a local network.) */
	  {
	    int dlen;
	    client_user = packet_get_string(&dlen);
	    packet_integrity_check(plen, 4 + dlen, type);
	  }

	  /* Try to authenticate using /etc/hosts.equiv and .rhosts. */
	  if (auth_rhosts(pw, client_user, options.ignore_rhosts,
			  options.strict_modes))
	    {
	      /* Authentication accepted. */
	      log("Rhosts authentication accepted for %.100s, remote %.100s on %.700s.",
		  user, client_user, get_canonical_hostname());
	      authenticated = 1;
	      xfree(client_user);
	      break;
	    }
	  log("Rhosts authentication failed for %.100s, remote %.100s.",
		user, client_user);
	  xfree(client_user);
	  break;

	case SSH_CMSG_AUTH_RHOSTS_RSA:
	  if (!options.rhosts_rsa_authentication)
	    {
	      log("Rhosts with RSA authentication disabled.");
	      break;
	    }

	  /* Rhosts authentication (also uses /etc/hosts.equiv) with RSA
	     host authentication. */
	  if (!privileged_port)
	    {
	      log("Rhosts authentication not available for connections from unprivileged port.");
	      break;
	    }

	  {
	    int ulen, elen, nlen;
	    /* Get client user name.  Note that we just have to trust
	       the client; root on the client machine can claim to be
	       any user. */
	    client_user = packet_get_string(&ulen);

	    /* Get the client host key. */
	    client_host_key_e = BN_new();
	    client_host_key_n = BN_new();
	    client_host_key_bits = packet_get_int();
	    packet_get_bignum(client_host_key_e, &elen);
	    packet_get_bignum(client_host_key_n, &nlen);

	    packet_integrity_check(plen, (4 + ulen) + 4 + elen + nlen, type);
	  }

	  /* Try to authenticate using /etc/hosts.equiv and .rhosts. */
	  if (auth_rhosts_rsa(pw, client_user,
			      client_host_key_bits, client_host_key_e,
			      client_host_key_n, options.ignore_rhosts,
			      options.strict_modes))
	    {
	      /* Authentication accepted. */
	      authenticated = 1;
	      xfree(client_user);
	      BN_clear_free(client_host_key_e);
	      BN_clear_free(client_host_key_n);
	      break;
	    }
	  log("Rhosts authentication failed for %.100s, remote %.100s.",
		user, client_user);
	  xfree(client_user);
	  BN_clear_free(client_host_key_e);
	  BN_clear_free(client_host_key_n);
	  break;
	  
	case SSH_CMSG_AUTH_RSA:
	  if (!options.rsa_authentication)
	    {
	      log("RSA authentication disabled.");
	      break;
	    }

	  /* RSA authentication requested. */
	  {
	    int nlen;
	    BIGNUM *n;
	    n = BN_new();
	    packet_get_bignum(n, &nlen);

	    packet_integrity_check(plen, nlen, type);
	    
	    if (auth_rsa(pw, n, options.strict_modes))
	      { 
		/* Successful authentication. */
		BN_clear_free(n);
		log("RSA authentication for %.100s accepted.", user);
		authenticated = 1;
		break;
	      }
	    BN_clear_free(n);
	    log("RSA authentication for %.100s failed.", user);
	  }
	  break;

	case SSH_CMSG_AUTH_PASSWORD:
	  if (!options.password_authentication)
	    {
	      log("Password authentication disabled.");
	      break;
	    }

	  /* Password authentication requested. */
	  /* Read user password.  It is in plain text, but was transmitted
	     over the encrypted channel so it is not visible to an outside
	     observer. */
	  {
	    int passw_len;
	    password = packet_get_string(&passw_len);
	    packet_integrity_check(plen, 4 + passw_len, type);
	  }

	  /* Try authentication with the password. */
	  if (auth_password(pw, password))
	    {
	      /* Successful authentication. */
	      /* Clear the password from memory. */
	      memset(password, 0, strlen(password));
	      xfree(password);
	      log("Password authentication for %.100s accepted.", user);
	      authenticated = 1;
	      break;
	    }
	  log("Password authentication for %.100s failed.", user);
	  memset(password, 0, strlen(password));
	  xfree(password);
	  break;

	case SSH_CMSG_AUTH_TIS:
	  /* TIS Authentication is unsupported */
	  log("TIS authentication disabled.");
	  break;

	default:
	  /* Any unknown messages will be ignored (and failure returned)
	     during authentication. */
	  log("Unknown message during authentication: type %d", type);
	  break; /* Respond with a failure message. */
	}
      /* If successfully authenticated, break out of loop. */
      if (authenticated)
	break;

      /* Send a message indicating that the authentication attempt failed. */
      packet_start(SSH_SMSG_FAILURE);
      packet_send();
      packet_write_wait();

      if (++authentication_failures >= MAX_AUTH_FAILURES) {
	packet_disconnect("Too many authentication failures for %.100s from %.200s", 
          pw->pw_name, get_canonical_hostname());
      }
    }

  /* Check if the user is logging in as root and root logins are disallowed. */
  if (pw->pw_uid == 0 && !options.permit_root_login)
    {
      if (forced_command)
	log("Root login accepted for forced command.", forced_command);
      else
	packet_disconnect("ROOT LOGIN REFUSED FROM %.200s", 
			  get_canonical_hostname());
    }

  /* The user has been authenticated and accepted. */
  packet_start(SSH_SMSG_SUCCESS);
  packet_send();
  packet_write_wait();

  /* Perform session preparation. */
  do_authenticated(pw);
}

/* Prepares for an interactive session.  This is called after the user has
   been successfully authenticated.  During this message exchange, pseudo
   terminals are allocated, X11, TCP/IP, and authentication agent forwardings
   are requested, etc. */

void do_authenticated(struct passwd *pw)
{
  int type;
  int compression_level = 0, enable_compression_after_reply = 0;
  int have_pty = 0, ptyfd = -1, ttyfd = -1, xauthfd = -1;
  int row, col, xpixel, ypixel, screen;
  char ttyname[64];
  char *command, *term = NULL, *display = NULL, *proto = NULL, *data = NULL;
  struct group *grp;
  gid_t tty_gid;
  mode_t tty_mode;
  int n_bytes;
  
  /* Cancel the alarm we set to limit the time taken for authentication. */
  alarm(0);

  /* Inform the channel mechanism that we are the server side and that
     the client may request to connect to any port at all.  (The user could
     do it anyway, and we wouldn\'t know what is permitted except by the
     client telling us, so we can equally well trust the client not to request
     anything bogus.) */
  channel_permit_all_opens();

  /* We stay in this loop until the client requests to execute a shell or a
     command. */
  while (1)
    {
      int plen, dlen;

      /* Get a packet from the client. */
      type = packet_read(&plen);
      
      /* Process the packet. */
      switch (type)
	{
	case SSH_CMSG_REQUEST_COMPRESSION:
	  packet_integrity_check(plen, 4, type);
	  compression_level = packet_get_int();
	  if (compression_level < 1 || compression_level > 9)
	    {
	      packet_send_debug("Received illegal compression level %d.",
				compression_level);
	      goto fail;
	    }
	  /* Enable compression after we have responded with SUCCESS. */
	  enable_compression_after_reply = 1;
	  break;

	case SSH_CMSG_REQUEST_PTY:
	  if (no_pty_flag)
	    {
	      debug("Allocating a pty not permitted for this authentication.");
	      goto fail;
	    }
	  if (have_pty)
	    packet_disconnect("Protocol error: you already have a pty.");

	  debug("Allocating pty.");

	  /* Allocate a pty and open it. */
	  if (!pty_allocate(&ptyfd, &ttyfd, ttyname))
	    {
	      error("Failed to allocate pty.");
	      goto fail;
	    }

	  /* Determine the group to make the owner of the tty. */
	  grp = getgrnam("tty");
	  if (grp)
	    {
	      tty_gid = grp->gr_gid;
	      tty_mode = S_IRUSR|S_IWUSR|S_IWGRP;
	    }
	  else
	    {
	      tty_gid = pw->pw_gid;
	      tty_mode = S_IRUSR|S_IWUSR|S_IWGRP|S_IWOTH;
	    }

	  /* Change ownership of the tty. */
	  if (chown(ttyname, pw->pw_uid, tty_gid) < 0)
	    fatal("chown(%.100s, %d, %d) failed: %.100s",
		  ttyname, pw->pw_uid, tty_gid, strerror(errno));
	  if (chmod(ttyname, tty_mode) < 0)
	    fatal("chmod(%.100s, 0%o) failed: %.100s",
		  ttyname, tty_mode, strerror(errno));

	  /* Get TERM from the packet.  Note that the value may be of arbitrary
	     length. */

	  term = packet_get_string(&dlen);
	  packet_integrity_check(dlen, strlen(term), type);
	  /* packet_integrity_check(plen, 4 + dlen + 4*4 + n_bytes, type); */
	  /* Remaining bytes */
	  n_bytes = plen - (4 + dlen + 4*4);
	  
	  if (strcmp(term, "") == 0)
	    term = NULL;

	  /* Get window size from the packet. */
	  row = packet_get_int();
	  col = packet_get_int();
	  xpixel = packet_get_int();
	  ypixel = packet_get_int();
	  pty_change_window_size(ptyfd, row, col, xpixel, ypixel);

	  /* Get tty modes from the packet. */
	  tty_parse_modes(ttyfd, &n_bytes);
	  packet_integrity_check(plen, 4 + dlen + 4*4 + n_bytes, type);

	  /* Indicate that we now have a pty. */
	  have_pty = 1;
	  break;

	case SSH_CMSG_X11_REQUEST_FORWARDING:
	  if (!options.x11_forwarding)
	    {
	      packet_send_debug("X11 forwarding disabled in server configuration file.");
	      goto fail;
	    }
#ifdef XAUTH_PATH
	  if (no_x11_forwarding_flag)
	    {
	      packet_send_debug("X11 forwarding not permitted for this authentication.");
	      goto fail;
	    }
	  debug("Received request for X11 forwarding with auth spoofing.");
	  if (display)
	    packet_disconnect("Protocol error: X11 display already set.");
	  {
	    int proto_len, data_len;
	    proto = packet_get_string(&proto_len);
	    data = packet_get_string(&data_len);
	    packet_integrity_check(plen, 4+proto_len + 4+data_len + 4, type);
	  }
	  if (packet_get_protocol_flags() & SSH_PROTOFLAG_SCREEN_NUMBER)
	    screen = packet_get_int();
	  else
	    screen = 0;
	  display = x11_create_display_inet(screen);
	  if (!display)
	    goto fail;

	  /* Setup to always have a local .Xauthority. */
	  xauthfile = xmalloc(MAXPATHLEN);
	  snprintf(xauthfile, MAXPATHLEN, "/tmp/XauthXXXXXX");
	  
	  if ((xauthfd = mkstemp(xauthfile)) != -1) {
	    fchown(xauthfd, pw->pw_uid, pw->pw_gid);
	    close(xauthfd);
	  }
	  else {
	    xfree(xauthfile);
	    xauthfile = NULL;
	  }
	  break;
#else /* XAUTH_PATH */
	  /* No xauth program; we won't accept forwarding with spoofing. */
	  packet_send_debug("No xauth program; cannot forward with spoofing.");
	  goto fail;
#endif /* XAUTH_PATH */

	case SSH_CMSG_AGENT_REQUEST_FORWARDING:
	  if (no_agent_forwarding_flag)
	    {
	      debug("Authentication agent forwarding not permitted for this authentication.");
	      goto fail;
	    }
	  debug("Received authentication agent forwarding request.");
	  auth_input_request_forwarding(pw);
	  break;

	case SSH_CMSG_PORT_FORWARD_REQUEST:
	  if (no_port_forwarding_flag)
	    {
	      debug("Port forwarding not permitted for this authentication.");
	      goto fail;
	    }
	  debug("Received TCP/IP port forwarding request.");
	  channel_input_port_forward_request(pw->pw_uid == 0);
	  break;

	case SSH_CMSG_EXEC_SHELL:
	  /* Set interactive/non-interactive mode. */
	  packet_set_interactive(have_pty || display != NULL, 
				 options.keepalives);
	    
	  if (forced_command != NULL)
	    goto do_forced_command;
	  debug("Forking shell.");
	  packet_integrity_check(plen, 0, type);
	  if (have_pty)
	    do_exec_pty(NULL, ptyfd, ttyfd, ttyname, pw, term, display, proto,
			data);
	  else
	    do_exec_no_pty(NULL, pw, display, proto, data);
	  return;

	case SSH_CMSG_EXEC_CMD:
	  /* Set interactive/non-interactive mode. */
	  packet_set_interactive(have_pty || display != NULL,
				 options.keepalives);

	  if (forced_command != NULL)
	    goto do_forced_command;
	  /* Get command from the packet. */
	  {
	    int dlen;
	    command = packet_get_string(&dlen);
	    debug("Executing command '%.500s'", command);
	    packet_integrity_check(plen, 4 + dlen, type);
	  }
	  if (have_pty)
	    do_exec_pty(command, ptyfd, ttyfd, ttyname, pw, term, display,
			proto, data);
	  else
	    do_exec_no_pty(command, pw, display, proto, data);
	  xfree(command);
	  return;

	case SSH_CMSG_MAX_PACKET_SIZE:
      	  debug("The server does not support limiting packet size.");
	  goto fail;

	default:
	  /* Any unknown messages in this phase are ignored, and a failure
	     message is returned. */
	  log("Unknown packet type received after authentication: %d", type);
	  goto fail;
	}

      /* The request was successfully processed. */
      packet_start(SSH_SMSG_SUCCESS);
      packet_send();
      packet_write_wait();

      /* Enable compression now that we have replied if appropriate. */
      if (enable_compression_after_reply)
	{
	  enable_compression_after_reply = 0;
	  packet_start_compression(compression_level);
	}

      continue;

    fail:
      /* The request failed. */
      packet_start(SSH_SMSG_FAILURE);
      packet_send();
      packet_write_wait();
      continue;
      
    do_forced_command:
      /* There is a forced command specified for this login.  Execute it. */
      debug("Executing forced command: %.900s", forced_command);
      if (have_pty)
	do_exec_pty(forced_command, ptyfd, ttyfd, ttyname, pw, term, display,
		    proto, data);
      else
	do_exec_no_pty(forced_command, pw, display, proto, data);
      return;
    }
}

/* This is called to fork and execute a command when we have no tty.  This
   will call do_child from the child, and server_loop from the parent after
   setting up file descriptors and such. */

void do_exec_no_pty(const char *command, struct passwd *pw,
		    const char *display, const char *auth_proto,
		    const char *auth_data)
{  
  int pid;

#ifdef USE_PIPES
  int pin[2], pout[2], perr[2];
  /* Allocate pipes for communicating with the program. */
  if (pipe(pin) < 0 || pipe(pout) < 0 || pipe(perr) < 0)
    packet_disconnect("Could not create pipes: %.100s",
		      strerror(errno));
#else /* USE_PIPES */
  int inout[2], err[2];
  /* Uses socket pairs to communicate with the program. */
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) < 0 ||
      socketpair(AF_UNIX, SOCK_STREAM, 0, err) < 0)
    packet_disconnect("Could not create socket pairs: %.100s",
		      strerror(errno));
#endif /* USE_PIPES */
  
  setproctitle("%s@notty", pw->pw_name);

  /* Fork the child. */
  if ((pid = fork()) == 0)
    {
      /* Child.  Reinitialize the log since the pid has changed. */
      log_init(av0, debug_flag && !inetd_flag, debug_flag, 
	       options.quiet_mode, options.log_facility);

      /* Create a new session and process group since the 4.4BSD setlogin()
	 affects the entire process group. */
      if (setsid() < 0)
	error("setsid failed: %.100s", strerror(errno));

#ifdef USE_PIPES
      /* Redirect stdin.  We close the parent side of the socket pair,
         and make the child side the standard input. */
      close(pin[1]);
      if (dup2(pin[0], 0) < 0)
	perror("dup2 stdin");
      close(pin[0]);
      
      /* Redirect stdout. */
      close(pout[0]);
      if (dup2(pout[1], 1) < 0)
	perror("dup2 stdout");
      close(pout[1]);

      /* Redirect stderr. */
      close(perr[0]);
      if (dup2(perr[1], 2) < 0)
	perror("dup2 stderr");
      close(perr[1]);
#else /* USE_PIPES */
      /* Redirect stdin, stdout, and stderr.  Stdin and stdout will use the
	 same socket, as some programs (particularly rdist) seem to depend
	 on it. */
      close(inout[1]);
      close(err[1]);
      if (dup2(inout[0], 0) < 0) /* stdin */
	perror("dup2 stdin");
      if (dup2(inout[0], 1) < 0) /* stdout.  Note: same socket as stdin. */
	perror("dup2 stdout");
      if (dup2(err[0], 2) < 0) /* stderr */
	perror("dup2 stderr");
#endif /* USE_PIPES */

      /* Do processing for the child (exec command etc). */
      do_child(command, pw, NULL, display, auth_proto, auth_data, NULL);
      /*NOTREACHED*/
    }
  if (pid < 0)
    packet_disconnect("fork failed: %.100s", strerror(errno));
#ifdef USE_PIPES
  /* We are the parent.  Close the child sides of the pipes. */
  close(pin[0]);
  close(pout[1]);
  close(perr[1]);

  /* Enter the interactive session. */
  server_loop(pid, pin[1], pout[0], perr[0]);
  /* server_loop has closed pin[1], pout[1], and perr[1]. */
#else /* USE_PIPES */
  /* We are the parent.  Close the child sides of the socket pairs. */
  close(inout[0]);
  close(err[0]);
  
  /* Enter the interactive session.  Note: server_loop must be able to handle
     the case that fdin and fdout are the same. */
  server_loop(pid, inout[1], inout[1], err[1]);
  /* server_loop has closed inout[1] and err[1]. */
#endif /* USE_PIPES */
}

struct pty_cleanup_context
{
  const char *ttyname;
  int pid;
};

/* Function to perform cleanup if we get aborted abnormally (e.g., due to a
   dropped connection). */

void pty_cleanup_proc(void *context)
{
  struct pty_cleanup_context *cu = context;

  debug("pty_cleanup_proc called");

#if defined(KRB4)
  /* Destroy user's ticket cache file. */
  (void) dest_tkt();
#endif /* KRB4 */
  
  /* Record that the user has logged out. */
  record_logout(cu->pid, cu->ttyname);

  /* Release the pseudo-tty. */
  pty_release(cu->ttyname);
}

/* This is called to fork and execute a command when we have a tty.  This
   will call do_child from the child, and server_loop from the parent after
   setting up file descriptors, controlling tty, updating wtmp, utmp,
   lastlog, and other such operations. */

void do_exec_pty(const char *command, int ptyfd, int ttyfd, 
		 const char *ttyname, struct passwd *pw, const char *term,
		 const char *display, const char *auth_proto, 
		 const char *auth_data)
{
  int pid, fdout;
  const char *hostname;
  time_t last_login_time;
  char buf[100], *time_string;
  FILE *f;
  char line[256];
  struct stat st;
  int quiet_login;
  struct sockaddr_in from;
  int fromlen;
  struct pty_cleanup_context cleanup_context;

  /* Get remote host name. */
  hostname = get_canonical_hostname();

  /* Get the time when the user last logged in.  Buf will be set to contain
     the hostname the last login was from. */
  if(!options.use_login) {
    last_login_time = get_last_login_time(pw->pw_uid, pw->pw_name,
					  buf, sizeof(buf));
  }

  setproctitle("%s@%s", pw->pw_name, strrchr(ttyname, '/') + 1);

  /* Fork the child. */
  if ((pid = fork()) == 0)
    { 
      pid = getpid();

      /* Child.  Reinitialize the log because the pid has changed. */
      log_init(av0, debug_flag && !inetd_flag, debug_flag, options.quiet_mode, 
	       options.log_facility);

      /* Close the master side of the pseudo tty. */
      close(ptyfd);

      /* Make the pseudo tty our controlling tty. */
      pty_make_controlling_tty(&ttyfd, ttyname);

      /* Redirect stdin from the pseudo tty. */
      if (dup2(ttyfd, fileno(stdin)) < 0)
	error("dup2 stdin failed: %.100s", strerror(errno));

      /* Redirect stdout to the pseudo tty. */
      if (dup2(ttyfd, fileno(stdout)) < 0)
	error("dup2 stdin failed: %.100s", strerror(errno));

      /* Redirect stderr to the pseudo tty. */
      if (dup2(ttyfd, fileno(stderr)) < 0)
	error("dup2 stdin failed: %.100s", strerror(errno));

      /* Close the extra descriptor for the pseudo tty. */
      close(ttyfd);

      /* Get IP address of client.  This is needed because we want to record 
	 where the user logged in from.  If the connection is not a socket,
	 let the ip address be 0.0.0.0. */
      memset(&from, 0, sizeof(from));
      if (packet_get_connection_in() == packet_get_connection_out())
	{
	  fromlen = sizeof(from);
	  if (getpeername(packet_get_connection_in(),
			  (struct sockaddr *)&from, &fromlen) < 0)
	    fatal("getpeername: %.100s", strerror(errno));
	}

      /* Record that there was a login on that terminal. */
      record_login(pid, ttyname, pw->pw_name, pw->pw_uid, hostname, 
		   &from);

      /* Check if .hushlogin exists. */
      snprintf(line, sizeof line, "%.200s/.hushlogin", pw->pw_dir);
      quiet_login = stat(line, &st) >= 0;
      
      /* If the user has logged in before, display the time of last login. 
         However, don't display anything extra if a command has been 
	 specified (so that ssh can be used to execute commands on a remote
         machine without users knowing they are going to another machine). 
         Login(1) will do this for us as well, so check if login(1) is used */
      if (command == NULL && last_login_time != 0 && !quiet_login && 
          !options.use_login)
	{
	  /* Convert the date to a string. */
	  time_string = ctime(&last_login_time);
	  /* Remove the trailing newline. */
	  if (strchr(time_string, '\n'))
	    *strchr(time_string, '\n') = 0;
	  /* Display the last login time.  Host if displayed if known. */
	  if (strcmp(buf, "") == 0)
	    printf("Last login: %s\r\n", time_string);
	  else
	    printf("Last login: %s from %s\r\n", time_string, buf);
	}

      /* Print /etc/motd unless a command was specified or printing it was
         disabled in server options or login(1) will be used.  Note that 
         some machines appear to print it in /etc/profile or similar. */
      if (command == NULL && options.print_motd && !quiet_login && 
          !options.use_login)
	{
	  /* Print /etc/motd if it exists. */
	  f = fopen("/etc/motd", "r");
	  if (f)
	    {
	      while (fgets(line, sizeof(line), f))
		fputs(line, stdout);
	      fclose(f);
	    }
	}

      /* Do common processing for the child, such as execing the command. */
      do_child(command, pw, term, display, auth_proto, auth_data, ttyname);
      /*NOTREACHED*/
    }
  if (pid < 0)
    packet_disconnect("fork failed: %.100s", strerror(errno));
  /* Parent.  Close the slave side of the pseudo tty. */
  close(ttyfd);
  
  /* Create another descriptor of the pty master side for use as the standard
     input.  We could use the original descriptor, but this simplifies code
     in server_loop.  The descriptor is bidirectional. */
  fdout = dup(ptyfd);
  if (fdout < 0)
    packet_disconnect("dup failed: %.100s", strerror(errno));

  /* Add a cleanup function to clear the utmp entry and record logout time
     in case we call fatal() (e.g., the connection gets closed). */
  cleanup_context.pid = pid;
  cleanup_context.ttyname = ttyname;
  fatal_add_cleanup(pty_cleanup_proc, (void *)&cleanup_context);

  /* Enter interactive session. */
  server_loop(pid, ptyfd, fdout, -1);
  /* server_loop has not closed ptyfd and fdout. */

  /* Cancel the cleanup function. */
  fatal_remove_cleanup(pty_cleanup_proc, (void *)&cleanup_context);

  /* Record that the user has logged out. */
  record_logout(pid, ttyname);

  /* Release the pseudo-tty. */
  pty_release(ttyname);

  /* Close the server side of the socket pairs.  We must do this after the
     pty cleanup, so that another process doesn't get this pty while we're
     still cleaning up. */
  close(ptyfd);
  close(fdout);
}

/* Sets the value of the given variable in the environment.  If the variable
   already exists, its value is overriden. */

void child_set_env(char ***envp, unsigned int *envsizep, const char *name,
		   const char *value)
{
  unsigned int i, namelen;
  char **env;

  /* Find the slot where the value should be stored.  If the variable already
     exists, we reuse the slot; otherwise we append a new slot at the end
     of the array, expanding if necessary. */
  env = *envp;
  namelen = strlen(name);
  for (i = 0; env[i]; i++)
    if (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
      break;
  if (env[i])
    {
      /* Name already exists.  Reuse the slot. */
      xfree(env[i]);
    }
  else
    {
      /* New variable.  Expand the array if necessary. */
      if (i >= (*envsizep) - 1)
	{
	  (*envsizep) += 50;
	  env = (*envp) = xrealloc(env, (*envsizep) * sizeof(char *));
	}

      /* Need to set the NULL pointer at end of array beyond the new 
	 slot. */
      env[i + 1] = NULL;
    }

  /* Allocate space and format the variable in the appropriate slot. */
  env[i] = xmalloc(strlen(name) + 1 + strlen(value) + 1);
  snprintf(env[i], strlen(name) + 1 + strlen(value) + 1, "%s=%s", name, value);
}

/* Reads environment variables from the given file and adds/overrides them
   into the environment.  If the file does not exist, this does nothing.
   Otherwise, it must consist of empty lines, comments (line starts with '#')
   and assignments of the form name=value.  No other forms are allowed. */

void read_environment_file(char ***env, unsigned int *envsize,
			   const char *filename)
{
  FILE *f;
  char buf[4096];
  char *cp, *value;
  
  /* Open the environment file. */
  f = fopen(filename, "r");
  if (!f)
    return;  /* Not found. */
  
  /* Process each line. */
  while (fgets(buf, sizeof(buf), f))
    {
      /* Skip leading whitespace. */
      for (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
	;

      /* Ignore empty and comment lines. */
      if (!*cp || *cp == '#' || *cp == '\n')
	continue;

      /* Remove newline. */
      if (strchr(cp, '\n'))
	*strchr(cp, '\n') = '\0';

      /* Find the equals sign.  Its lack indicates badly formatted line. */
      value = strchr(cp, '=');
      if (value == NULL)
	{
	  fprintf(stderr, "Bad line in %.100s: %.200s\n", filename, buf);
	  continue;
	}

      /* Replace the equals sign by nul, and advance value to the value 
	 string. */
      *value = '\0';
      value++;

      /* Set the value in environment. */
      child_set_env(env, envsize, cp, value);
    }
  
  fclose(f);
}

/* Performs common processing for the child, such as setting up the 
   environment, closing extra file descriptors, setting the user and group 
   ids, and executing the command or shell. */

void do_child(const char *command, struct passwd *pw, const char *term,
	      const char *display, const char *auth_proto, 
	      const char *auth_data, const char *ttyname)
{
  const char *shell, *cp = NULL;
  char buf[256];
  FILE *f;
  unsigned int envsize, i;
  char **env;
  extern char **environ;
  struct stat st;
  char *argv[10];

  /* Check /etc/nologin. */
  f = fopen("/etc/nologin", "r");
  if (f)
    { /* /etc/nologin exists.  Print its contents and exit. */
      while (fgets(buf, sizeof(buf), f))
	fputs(buf, stderr);
      fclose(f);
      if (pw->pw_uid != 0)
	exit(254);
    }

  /* Set login name in the kernel. */
  if (setlogin(pw->pw_name) < 0)
    error("setlogin failed: %s", strerror(errno));

  /* Set uid, gid, and groups. */
  /* Login(1) does this as well, and it needs uid 0 for the "-h" switch,
     so we let login(1) to this for us. */
  if(!options.use_login) {
    if (getuid() == 0 || geteuid() == 0)
      { 
        if (setgid(pw->pw_gid) < 0)
          {
            perror("setgid");
            exit(1);
          }
        /* Initialize the group list. */
        if (initgroups(pw->pw_name, pw->pw_gid) < 0)
          {
            perror("initgroups");
            exit(1);
          }
        endgrent();
   
        /* Permanently switch to the desired uid. */
        permanently_set_uid(pw->pw_uid);
      }
   
    if (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
      fatal("Failed to set uids to %d.", (int)pw->pw_uid);
  }

  /* Get the shell from the password data.  An empty shell field is legal,
     and means /bin/sh. */
  shell = (pw->pw_shell[0] == '\0') ? _PATH_BSHELL : pw->pw_shell;

#ifdef AFS
  /* Try to get AFS tokens for the local cell. */
  if (k_hasafs()) {
    char cell[64];
    
    if (k_afs_cell_of_file(pw->pw_dir, cell, sizeof(cell)) == 0)
      krb_afslog(cell, 0);

    krb_afslog(0, 0);
  }
#endif /* AFS */
  
  /* Initialize the environment.  In the first part we allocate space for
     all environment variables. */
  envsize = 100;
  env = xmalloc(envsize * sizeof(char *));
  env[0] = NULL;

  if(!options.use_login) {
    /* Set basic environment. */
    child_set_env(&env, &envsize, "USER", pw->pw_name);
    child_set_env(&env, &envsize, "LOGNAME", pw->pw_name);
    child_set_env(&env, &envsize, "HOME", pw->pw_dir);
    child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
   
    snprintf(buf, sizeof buf, "%.200s/%.50s",
      _PATH_MAILDIR, pw->pw_name);
    child_set_env(&env, &envsize, "MAIL", buf);
   
    /* Normal systems set SHELL by default. */
    child_set_env(&env, &envsize, "SHELL", shell);
  }

  /* Let it inherit timezone if we have one. */
  if (getenv("TZ"))
    child_set_env(&env, &envsize, "TZ", getenv("TZ"));

  /* Set custom environment options from RSA authentication. */
  while (custom_environment) 
    {
      struct envstring *ce = custom_environment;
      char *s = ce->s;
      int i;
      for (i = 0; s[i] != '=' && s[i]; i++)
	;
      if (s[i] == '=') 
	{
	  s[i] = 0;
	  child_set_env(&env, &envsize, s, s + i + 1);
	}
      custom_environment = ce->next;
      xfree(ce->s);
      xfree(ce);
    }

  /* Set SSH_CLIENT. */
  snprintf(buf, sizeof buf, "%.50s %d %d", 
	  get_remote_ipaddr(), get_remote_port(), options.port);
  child_set_env(&env, &envsize, "SSH_CLIENT", buf);

  /* Set SSH_TTY if we have a pty. */
  if (ttyname)
    child_set_env(&env, &envsize, "SSH_TTY", ttyname);

  /* Set TERM if we have a pty. */
  if (term)
    child_set_env(&env, &envsize, "TERM", term);

  /* Set DISPLAY if we have one. */
  if (display)
    child_set_env(&env, &envsize, "DISPLAY", display);

#ifdef KRB4
  if (ticket)
    child_set_env(&env, &envsize, "KRBTKFILE", ticket);
#endif /* KRB4 */

  /* Set XAUTHORITY to always be a local file. */
  if (xauthfile)
      child_set_env(&env, &envsize, "XAUTHORITY", xauthfile);

  /* Set variable for forwarded authentication connection, if we have one. */
  if (auth_get_socket_name() != NULL)
      child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME, 
		    auth_get_socket_name());

  /* Read $HOME/.ssh/environment. */
  if(!options.use_login) {
    snprintf(buf, sizeof buf, "%.200s/.ssh/environment", pw->pw_dir);
    read_environment_file(&env, &envsize, buf);
  }

  /* If debugging, dump the environment to stderr. */
  if (debug_flag)
    {
      fprintf(stderr, "Environment:\n");
      for (i = 0; env[i]; i++)
	fprintf(stderr, "  %.200s\n", env[i]);
    }

  /* Close the connection descriptors; note that this is the child, and the 
     server will still have the socket open, and it is important that we
     do not shutdown it.  Note that the descriptors cannot be closed before
     building the environment, as we call get_remote_ipaddr there. */
  if (packet_get_connection_in() == packet_get_connection_out())
    close(packet_get_connection_in());
  else
    {
      close(packet_get_connection_in());
      close(packet_get_connection_out());
    }
  /* Close all descriptors related to channels.  They will still remain
     open in the parent. */
  channel_close_all();

  /* Close any extra file descriptors.  Note that there may still be
     descriptors left by system functions.  They will be closed later. */
  endpwent();
  endhostent();

  /* Close any extra open file descriptors so that we don\'t have them
     hanging around in clients.  Note that we want to do this after
     initgroups, because at least on Solaris 2.3 it leaves file descriptors
     open. */
  for (i = 3; i < 64; i++)
    close(i);

  /* Change current directory to the user\'s home directory. */
  if (chdir(pw->pw_dir) < 0)
    fprintf(stderr, "Could not chdir to home directory %s: %s\n",
	    pw->pw_dir, strerror(errno));

  /* Must take new environment into use so that .ssh/rc, /etc/sshrc and
     xauth are run in the proper environment. */
  environ = env;

  /* Run $HOME/.ssh/rc, /etc/sshrc, or xauth (whichever is found first
     in this order). */
  if(!options.use_login) {
    if (stat(SSH_USER_RC, &st) >= 0)
      {
        if (debug_flag)
      	fprintf(stderr, "Running /bin/sh %s\n", SSH_USER_RC);
 
        f = popen("/bin/sh " SSH_USER_RC, "w");
        if (f)
      	{
      	  if (auth_proto != NULL && auth_data != NULL)
      	    fprintf(f, "%s %s\n", auth_proto, auth_data);
      	  pclose(f);
      	}
        else
      	fprintf(stderr, "Could not run %s\n", SSH_USER_RC);
      }
    else
      if (stat(SSH_SYSTEM_RC, &st) >= 0)
        {
      	if (debug_flag)
      	  fprintf(stderr, "Running /bin/sh %s\n", SSH_SYSTEM_RC);
 
      	f = popen("/bin/sh " SSH_SYSTEM_RC, "w");
      	if (f)
      	  {
      	    if (auth_proto != NULL && auth_data != NULL)
      	      fprintf(f, "%s %s\n", auth_proto, auth_data);
      	    pclose(f);
      	  }
      	else
      	  fprintf(stderr, "Could not run %s\n", SSH_SYSTEM_RC);
        }
#ifdef XAUTH_PATH
      else
        {
      	/* Add authority data to .Xauthority if appropriate. */
      	if (auth_proto != NULL && auth_data != NULL)
      	  {
      	    if (debug_flag)
      	      fprintf(stderr, "Running %.100s add %.100s %.100s %.100s\n",
      		      XAUTH_PATH, display, auth_proto, auth_data);
      	    
      	    f = popen(XAUTH_PATH " -q -", "w");
      	    if (f)
      	      {
      		fprintf(f, "add %s %s %s\n", display, auth_proto, auth_data);
      		fclose(f);
      	      }
      	    else
      	      fprintf(stderr, "Could not run %s -q -\n", XAUTH_PATH);
      	  }
        }
#endif /* XAUTH_PATH */

    /* Get the last component of the shell name. */
    cp = strrchr(shell, '/');
    if (cp)
      cp++;
    else
      cp = shell;
  }

  /* If we have no command, execute the shell.  In this case, the shell name
     to be passed in argv[0] is preceded by '-' to indicate that this is
     a login shell. */
  if (!command)
    {
      if(!options.use_login) {
        char buf[256];

        /* Check for mail if we have a tty and it was enabled in server options. */
        if (ttyname && options.check_mail) {
          char *mailbox;
          struct stat mailstat;
          mailbox = getenv("MAIL");
          if(mailbox != NULL) {
            if(stat(mailbox, &mailstat) != 0 || mailstat.st_size == 0) {
              printf("No mail.\n");
            } else if(mailstat.st_mtime < mailstat.st_atime) {
              printf("You have mail.\n");
            } else {
              printf("You have new mail.\n");
            }
          }
        }
        /* Start the shell.  Set initial character to '-'. */
        buf[0] = '-';
        strncpy(buf + 1, cp, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;
        /* Execute the shell. */
        argv[0] = buf;
        argv[1] = NULL;
        execve(shell, argv, env);
        /* Executing the shell failed. */
        perror(shell);
        exit(1);

      } else {
        /* Launch login(1). */

        execl("/usr/bin/login", "login", "-h", get_remote_ipaddr(), "-p", "-f", "--", pw->pw_name, NULL);

        /* Login couldn't be executed, die. */

        perror("login");
        exit(1);
      }
    }

  /* Execute the command using the user's shell.  This uses the -c option
     to execute the command. */
  argv[0] = (char *)cp;
  argv[1] = "-c";
  argv[2] = (char *)command;
  argv[3] = NULL;
  execve(shell, argv, env);
  perror(shell);
  exit(1);
}
