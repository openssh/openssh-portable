/*

servconf.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Aug 21 15:48:58 1995 ylo

*/

#include "includes.h"
RCSID("$Id: servconf.c,v 1.1 1999/10/27 03:42:45 damien Exp $");

#include "ssh.h"
#include "servconf.h"
#include "xmalloc.h"

/* Initializes the server options to their default values. */

void initialize_server_options(ServerOptions *options)
{
  memset(options, 0, sizeof(*options));
  options->port = -1;
  options->listen_addr.s_addr = htonl(INADDR_ANY);
  options->host_key_file = NULL;
  options->server_key_bits = -1;
  options->login_grace_time = -1;
  options->key_regeneration_time = -1;
  options->permit_root_login = -1;
  options->ignore_rhosts = -1;
  options->quiet_mode = -1;
  options->fascist_logging = -1;
  options->print_motd = -1;
  options->check_mail = -1;
  options->x11_forwarding = -1;
  options->x11_display_offset = -1;
  options->strict_modes = -1;
  options->keepalives = -1;
  options->log_facility = (SyslogFacility)-1;
  options->rhosts_authentication = -1;
  options->rhosts_rsa_authentication = -1;
  options->rsa_authentication = -1;
#ifdef KRB4
  options->kerberos_authentication = -1;
  options->kerberos_or_local_passwd = -1;
  options->kerberos_ticket_cleanup = -1;
#endif
#ifdef AFS
  options->kerberos_tgt_passing = -1;
  options->afs_token_passing = -1;
#endif
  options->password_authentication = -1;
#ifdef SKEY
  options->skey_authentication = -1;
#endif
  options->permit_empty_passwd = -1;
  options->use_login = -1;
  options->num_allow_users = 0;
  options->num_deny_users = 0;
  options->num_allow_groups = 0;
  options->num_deny_groups = 0;
}

void fill_default_server_options(ServerOptions *options)
{
  if (options->port == -1)
    {
      struct servent *sp;

      sp = getservbyname(SSH_SERVICE_NAME, "tcp");
      if (sp)
	options->port = ntohs(sp->s_port);
      else
	options->port = SSH_DEFAULT_PORT;
      endservent();
    }
  if (options->host_key_file == NULL)
    options->host_key_file = HOST_KEY_FILE;
  if (options->server_key_bits == -1)
    options->server_key_bits = 768;
  if (options->login_grace_time == -1)
    options->login_grace_time = 600;
  if (options->key_regeneration_time == -1)
    options->key_regeneration_time = 3600;
  if (options->permit_root_login == -1)
    options->permit_root_login = 1;		 /* yes */
  if (options->ignore_rhosts == -1)
    options->ignore_rhosts = 0;
  if (options->quiet_mode == -1)
    options->quiet_mode = 0;
  if (options->check_mail == -1)
    options->check_mail = 0;
  if (options->fascist_logging == -1)
    options->fascist_logging = 1;
  if (options->print_motd == -1)
    options->print_motd = 1;
  if (options->x11_forwarding == -1)
    options->x11_forwarding = 1;
  if (options->x11_display_offset == -1)
    options->x11_display_offset = 1;
  if (options->strict_modes == -1)
    options->strict_modes = 1;
  if (options->keepalives == -1)
    options->keepalives = 1;
  if (options->log_facility == (SyslogFacility)(-1))
    options->log_facility = SYSLOG_FACILITY_AUTH;
  if (options->rhosts_authentication == -1)
    options->rhosts_authentication = 0;
  if (options->rhosts_rsa_authentication == -1)
    options->rhosts_rsa_authentication = 1;
  if (options->rsa_authentication == -1)
    options->rsa_authentication = 1;
#ifdef KRB4
  if (options->kerberos_authentication == -1)
    options->kerberos_authentication = (access(KEYFILE, R_OK) == 0);
  if (options->kerberos_or_local_passwd == -1)
    options->kerberos_or_local_passwd = 1;
  if (options->kerberos_ticket_cleanup == -1)
    options->kerberos_ticket_cleanup = 1;
#endif /* KRB4 */
#ifdef AFS
  if (options->kerberos_tgt_passing == -1)
    options->kerberos_tgt_passing = 0;
  if (options->afs_token_passing == -1)
    options->afs_token_passing = k_hasafs();
#endif /* AFS */
  if (options->password_authentication == -1)
    options->password_authentication = 1;
#ifdef SKEY
  if (options->skey_authentication == -1)
    options->skey_authentication = 1;
#endif
  if (options->permit_empty_passwd == -1)
    options->permit_empty_passwd = 1;
  if (options->use_login == -1)
    options->use_login = 0;
}

#define WHITESPACE " \t\r\n"

/* Keyword tokens. */
typedef enum 
{
  sPort, sHostKeyFile, sServerKeyBits, sLoginGraceTime, sKeyRegenerationTime,
  sPermitRootLogin, sQuietMode, sFascistLogging, sLogFacility,
  sRhostsAuthentication, sRhostsRSAAuthentication, sRSAAuthentication,
#ifdef KRB4
  sKerberosAuthentication, sKerberosOrLocalPasswd, sKerberosTicketCleanup,
#endif
#ifdef AFS
  sKerberosTgtPassing, sAFSTokenPassing,
#endif
#ifdef SKEY
  sSkeyAuthentication,
#endif
  sPasswordAuthentication, sListenAddress,
  sPrintMotd, sIgnoreRhosts, sX11Forwarding, sX11DisplayOffset,
  sStrictModes, sEmptyPasswd, sRandomSeedFile, sKeepAlives, sCheckMail,
  sUseLogin, sAllowUsers, sDenyUsers, sAllowGroups, sDenyGroups

} ServerOpCodes;

/* Textual representation of the tokens. */
static struct
{
  const char *name;
  ServerOpCodes opcode;
} keywords[] =
{
  { "port", sPort },
  { "hostkey", sHostKeyFile },
  { "serverkeybits", sServerKeyBits },
  { "logingracetime", sLoginGraceTime },
  { "keyregenerationinterval", sKeyRegenerationTime },
  { "permitrootlogin", sPermitRootLogin },
  { "quietmode", sQuietMode },
  { "fascistlogging", sFascistLogging },
  { "syslogfacility", sLogFacility },
  { "rhostsauthentication", sRhostsAuthentication },
  { "rhostsrsaauthentication", sRhostsRSAAuthentication },
  { "rsaauthentication", sRSAAuthentication },
#ifdef KRB4
  { "kerberosauthentication", sKerberosAuthentication },
  { "kerberosorlocalpasswd", sKerberosOrLocalPasswd },
  { "kerberosticketcleanup", sKerberosTicketCleanup },
#endif
#ifdef AFS
  { "kerberostgtpassing", sKerberosTgtPassing },
  { "afstokenpassing", sAFSTokenPassing },
#endif
  { "passwordauthentication", sPasswordAuthentication },
#ifdef SKEY
  { "skeyauthentication", sSkeyAuthentication },
#endif
  { "checkmail", sCheckMail },
  { "listenaddress", sListenAddress },
  { "printmotd", sPrintMotd },
  { "ignorerhosts", sIgnoreRhosts },
  { "x11forwarding", sX11Forwarding },
  { "x11displayoffset", sX11DisplayOffset },
  { "strictmodes", sStrictModes },
  { "permitemptypasswords", sEmptyPasswd },
  { "uselogin", sUseLogin },
  { "randomseed", sRandomSeedFile },
  { "keepalive", sKeepAlives },
  { "allowusers", sAllowUsers },
  { "denyusers", sDenyUsers },
  { "allowgroups", sAllowGroups },
  { "denygroups", sDenyGroups },
  { NULL, 0 }
};

static struct 
{
  const char *name;
  SyslogFacility facility;
} log_facilities[] =
{
  { "DAEMON", SYSLOG_FACILITY_DAEMON },
  { "USER", SYSLOG_FACILITY_USER },
  { "AUTH", SYSLOG_FACILITY_AUTH },
  { "LOCAL0", SYSLOG_FACILITY_LOCAL0 },
  { "LOCAL1", SYSLOG_FACILITY_LOCAL1 },
  { "LOCAL2", SYSLOG_FACILITY_LOCAL2 },
  { "LOCAL3", SYSLOG_FACILITY_LOCAL3 },
  { "LOCAL4", SYSLOG_FACILITY_LOCAL4 },
  { "LOCAL5", SYSLOG_FACILITY_LOCAL5 },
  { "LOCAL6", SYSLOG_FACILITY_LOCAL6 },
  { "LOCAL7", SYSLOG_FACILITY_LOCAL7 },
  { NULL, 0 }
};

/* Returns the number of the token pointed to by cp of length len.
   Never returns if the token is not known. */

static ServerOpCodes parse_token(const char *cp, const char *filename,
				 int linenum)
{
  unsigned int i;

  for (i = 0; keywords[i].name; i++)
    if (strcmp(cp, keywords[i].name) == 0)
      return keywords[i].opcode;

  fprintf(stderr, "%s line %d: Bad configuration option: %s\n", 
	  filename, linenum, cp);
  exit(1);
}

/* Reads the server configuration file. */

void read_server_config(ServerOptions *options, const char *filename)
{
  FILE *f;
  char line[1024];
  char *cp, **charptr;
  int linenum, *intptr, i, value;
  ServerOpCodes opcode;

  f = fopen(filename, "r");
  if (!f)
    {
      perror(filename);
      exit(1);
    }

  linenum = 0;
  while (fgets(line, sizeof(line), f))
    {
      linenum++;
      cp = line + strspn(line, WHITESPACE);
      if (!*cp || *cp == '#')
	continue;
      cp = strtok(cp, WHITESPACE);
      {
	char *t = cp;
	for (; *t != 0; t++)
	  if ('A' <= *t && *t <= 'Z')
	    *t = *t - 'A' + 'a';	/* tolower */
      
      }
      opcode = parse_token(cp, filename, linenum);
      switch (opcode)
	{
	case sPort:
	  intptr = &options->port;
	parse_int:
	  cp = strtok(NULL, WHITESPACE);
	  if (!cp)
	    {
	      fprintf(stderr, "%s line %d: missing integer value.\n", 
		      filename, linenum);
	      exit(1);
	    }
	  value = atoi(cp);
	  if (*intptr == -1)
	    *intptr = value;
	  break;

	case sServerKeyBits:
	  intptr = &options->server_key_bits;
	  goto parse_int;

	case sLoginGraceTime:
	  intptr = &options->login_grace_time;
	  goto parse_int;
	  
	case sKeyRegenerationTime:
	  intptr = &options->key_regeneration_time;
	  goto parse_int;

	case sListenAddress:
	  cp = strtok(NULL, WHITESPACE);
	  if (!cp)
	    {
	      fprintf(stderr, "%s line %d: missing inet addr.\n",
		      filename, linenum);
	      exit(1);
	    }
	  options->listen_addr.s_addr = inet_addr(cp);
	  break;

	case sHostKeyFile:
	  charptr = &options->host_key_file;
	  cp = strtok(NULL, WHITESPACE);
	  if (!cp)
	    {
	      fprintf(stderr, "%s line %d: missing file name.\n",
		      filename, linenum);
	      exit(1);
	    }
	  if (*charptr == NULL)
	    *charptr = tilde_expand_filename(cp, getuid());
	  break;

	case sRandomSeedFile:
	  fprintf(stderr, "%s line %d: \"randomseed\" option is obsolete.\n",
		  filename, linenum);
	  cp = strtok(NULL, WHITESPACE);
	  break;

	case sPermitRootLogin:
	  intptr = &options->permit_root_login;
	  cp = strtok(NULL, WHITESPACE);
	  if (!cp)
	    {
	      fprintf(stderr, "%s line %d: missing yes/without-password/no argument.\n",
		      filename, linenum);
	      exit(1);
	    }
	  if (strcmp(cp, "without-password") == 0)
	    value = 2;
	  else if (strcmp(cp, "yes") == 0)
	    value = 1;
	  else if (strcmp(cp, "no") == 0)
	    value = 0;
	  else
	    {
	      fprintf(stderr, "%s line %d: Bad yes/without-password/no argument: %s\n", 
	      	filename, linenum, cp);
	      exit(1);
	    }
	  if (*intptr == -1)
	    *intptr = value;
	  break;

	case sIgnoreRhosts:
	  intptr = &options->ignore_rhosts;
	parse_flag:
	  cp = strtok(NULL, WHITESPACE);
	  if (!cp)
	    {
	      fprintf(stderr, "%s line %d: missing yes/no argument.\n",
		      filename, linenum);
	      exit(1);
	    }
	  if (strcmp(cp, "yes") == 0)
	    value = 1;
	  else
	    if (strcmp(cp, "no") == 0)
	      value = 0;
	    else
	      {
		fprintf(stderr, "%s line %d: Bad yes/no argument: %s\n", 
			filename, linenum, cp);
		exit(1);
	      }
	  if (*intptr == -1)
	    *intptr = value;
	  break;
	  
	case sQuietMode:
	  intptr = &options->quiet_mode;
	  goto parse_flag;

	case sFascistLogging:
	  intptr = &options->fascist_logging;
	  goto parse_flag;

	case sRhostsAuthentication:
	  intptr = &options->rhosts_authentication;
	  goto parse_flag;

	case sRhostsRSAAuthentication:
	  intptr = &options->rhosts_rsa_authentication;
	  goto parse_flag;
	  
	case sRSAAuthentication:
	  intptr = &options->rsa_authentication;
	  goto parse_flag;
	  
#ifdef KRB4
	case sKerberosAuthentication:
	  intptr = &options->kerberos_authentication;
	  goto parse_flag;
	  
 	case sKerberosOrLocalPasswd:
 	  intptr = &options->kerberos_or_local_passwd;
 	  goto parse_flag;

	case sKerberosTicketCleanup:
	  intptr = &options->kerberos_ticket_cleanup;
	  goto parse_flag;
#endif
	  
#ifdef AFS
	case sKerberosTgtPassing:
	  intptr = &options->kerberos_tgt_passing;
	  goto parse_flag;

	case sAFSTokenPassing:
	  intptr = &options->afs_token_passing;
	  goto parse_flag;
#endif

	case sPasswordAuthentication:
	  intptr = &options->password_authentication;
	  goto parse_flag;

        case sCheckMail:
          intptr = &options->check_mail;
          goto parse_flag;

#ifdef SKEY
	case sSkeyAuthentication:
	  intptr = &options->skey_authentication;
	  goto parse_flag;
#endif

	case sPrintMotd:
	  intptr = &options->print_motd;
	  goto parse_flag;

	case sX11Forwarding:
	  intptr = &options->x11_forwarding;
	  goto parse_flag;

	case sX11DisplayOffset:
	  intptr = &options->x11_display_offset;
	  goto parse_int;

	case sStrictModes:
	  intptr = &options->strict_modes;
	  goto parse_flag;

	case sKeepAlives:
	  intptr = &options->keepalives;
	  goto parse_flag;
	  
	case sEmptyPasswd:
	  intptr = &options->permit_empty_passwd;
	  goto parse_flag;

        case sUseLogin:
          intptr = &options->use_login;
          goto parse_flag;

	case sLogFacility:
	  cp = strtok(NULL, WHITESPACE);
	  if (!cp)
	    {
	      fprintf(stderr, "%s line %d: missing facility name.\n",
		      filename, linenum);
	      exit(1);
	    }
	  for (i = 0; log_facilities[i].name; i++)
	    if (strcmp(log_facilities[i].name, cp) == 0)
	      break;
	  if (!log_facilities[i].name)
	    {
	      fprintf(stderr, "%s line %d: unsupported log facility %s\n",
		      filename, linenum, cp);
	      exit(1);
	    }
	  if (options->log_facility == (SyslogFacility)(-1))
	    options->log_facility = log_facilities[i].facility;
	  break;
	  
	case sAllowUsers:
	  while ((cp = strtok(NULL, WHITESPACE)))
	    {
	      if (options->num_allow_users >= MAX_ALLOW_USERS)
		{
		  fprintf(stderr, "%s line %d: too many allow users.\n",
			  filename, linenum);
		  exit(1);
		}
	      options->allow_users[options->num_allow_users++] = xstrdup(cp);
	    }
	  break;

	case sDenyUsers:
	  while ((cp = strtok(NULL, WHITESPACE)))
	    {
	      if (options->num_deny_users >= MAX_DENY_USERS)
		{
		  fprintf(stderr, "%s line %d: too many deny users.\n",
			  filename, linenum);
		  exit(1);
		}
	      options->deny_users[options->num_deny_users++] = xstrdup(cp);
	    }
	  break;

	case sAllowGroups:
	  while ((cp = strtok(NULL, WHITESPACE)))
	    {
	      if (options->num_allow_groups >= MAX_ALLOW_GROUPS)
		{
		  fprintf(stderr, "%s line %d: too many allow groups.\n",
			  filename, linenum);
		  exit(1);
		}
	      options->allow_groups[options->num_allow_groups++] = xstrdup(cp);
	    }
	  break;

	case sDenyGroups:
	  while ((cp = strtok(NULL, WHITESPACE)))
	    {
	      if (options->num_deny_groups >= MAX_DENY_GROUPS)
		{
		  fprintf(stderr, "%s line %d: too many deny groups.\n",
			  filename, linenum);
		  exit(1);
		}
	      options->deny_groups[options->num_deny_groups++] = xstrdup(cp);
	    }
	  break;

	default:
	  fprintf(stderr, "%s line %d: Missing handler for opcode %s (%d)\n",
		  filename, linenum, cp, opcode);
	  exit(1);
	}
      if (strtok(NULL, WHITESPACE) != NULL)
	{
	  fprintf(stderr, "%s line %d: garbage at end of line.\n",
		  filename, linenum);
	  exit(1);
	}
    }
  fclose(f);
}
