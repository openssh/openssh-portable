#ifndef _CONFIG_H
#define _CONFIG_H

/* Generated automatically from acconfig.h by autoheader. */
/* Please make your changes there */

@TOP@

/* If your header files don't define LOGIN_PROGRAM, then use this (detected) */
/* from environment and PATH */
#undef LOGIN_PROGRAM_FALLBACK

/* Define if your password has a pw_class field */
#undef HAVE_PW_CLASS_IN_PASSWD

/* Define if your socketpair() has bugs */
#undef USE_PIPES

/* Define if your system's struct sockaddr_un has a sun_len member */
#undef HAVE_SUN_LEN_IN_SOCKADDR_UN

/* Define if you system's inet_ntoa is busted (e.g. Irix gcc issue) */
#undef BROKEN_INET_NTOA

/* Define if your system defines sys_errlist[] */
#undef HAVE_SYS_ERRLIST

/* Define if your system defines sys_nerr */
#undef HAVE_SYS_NERR

/* Define if your system choked on IP TOS setting */
#undef IP_TOS_IS_BROKEN

/* Define if you have the getuserattr function.  */
#undef HAVE_GETUSERATTR

/* Work around problematic Linux PAM modules handling of PAM_TTY */
#undef PAM_TTY_KLUDGE

/* Use PIPES instead of a socketpair() */
#undef USE_PIPES

/* Define if your snprintf is busted */
#undef BROKEN_SNPRINTF

/* Define if you are on NeXT */
#undef HAVE_NEXT

/* Define if you want to disable PAM support */
#undef DISABLE_PAM

/* Define if you want to enable AIX4's authenticate function */
#undef WITH_AIXAUTHENTICATE

/* Define if you have/want arrays (cluster-wide session managment, not C arrays) */
#undef WITH_IRIX_ARRAY

/* Define if you want IRIX project management */
#undef WITH_IRIX_PROJECT

/* Define if you want IRIX audit trails */
#undef WITH_IRIX_AUDIT

/* Location of random number pool  */
#undef RANDOM_POOL

/* Location of EGD random number socket */
#undef EGD_SOCKET

/* Builtin PRNG command timeout */
#undef ENTROPY_TIMEOUT_MSEC

/* Define if you want to install preformatted manpages.*/
#undef MANTYPE

/* Define if your ssl headers are included with #include <openssl/header.h>  */
#undef HAVE_OPENSSL

/* Define if you are linking against RSAref.  Used only to print the right
 * message at run-time. */
#undef RSAREF

/* struct utmp and struct utmpx fields */
#undef HAVE_HOST_IN_UTMP
#undef HAVE_HOST_IN_UTMPX
#undef HAVE_ADDR_IN_UTMP
#undef HAVE_ADDR_IN_UTMPX
#undef HAVE_ADDR_V6_IN_UTMP
#undef HAVE_ADDR_V6_IN_UTMPX
#undef HAVE_SYSLEN_IN_UTMPX
#undef HAVE_PID_IN_UTMP
#undef HAVE_TYPE_IN_UTMP
#undef HAVE_TYPE_IN_UTMPX
#undef HAVE_TV_IN_UTMP
#undef HAVE_TV_IN_UTMPX
#undef HAVE_ID_IN_UTMP
#undef HAVE_ID_IN_UTMPX
#undef HAVE_EXIT_IN_UTMP
#undef HAVE_TIME_IN_UTMP
#undef HAVE_TIME_IN_UTMPX

/* Define if you don't want to use your system's login() call */
#undef DISABLE_LOGIN

/* Define if you don't want to use pututline() etc. to write [uw]tmp */
#undef DISABLE_PUTUTLINE

/* Define if you don't want to use pututxline() etc. to write [uw]tmpx */
#undef DISABLE_PUTUTXLINE

/* Define if you don't want to use lastlog */
#undef DISABLE_LASTLOG

/* Define if you don't want to use utmp */
#undef DISABLE_UTMP

/* Define if you don't want to use utmpx */
#undef DISABLE_UTMPX

/* Define if you don't want to use wtmp */
#undef DISABLE_WTMP

/* Define if you don't want to use wtmpx */
#undef DISABLE_WTMPX

/* Define if you want to specify the path to your lastlog file */
#undef CONF_LASTLOG_FILE

/* Define if you want to specify the path to your utmp file */
#undef CONF_UTMP_FILE

/* Define if you want to specify the path to your wtmp file */
#undef CONF_WTMP_FILE

/* Define if you want to specify the path to your utmpx file */
#undef CONF_UTMPX_FILE

/* Define if you want to specify the path to your wtmpx file */
#undef CONF_WTMPX_FILE

/* Define is libutil has login() function */
#undef HAVE_LIBUTIL_LOGIN

/* Define if you want external askpass support */
#undef USE_EXTERNAL_ASKPASS

/* Define if libc defines __progname */
#undef HAVE___PROGNAME

/* Define if you want Kerberos 4 support */
#undef KRB4

/* Define if you want AFS support */
#undef AFS

/* Define if you want S/Key support */
#undef SKEY

/* Define if you want TCP Wrappers support */
#undef LIBWRAP

/* Define if your libraries define login() */
#undef HAVE_LOGIN

/* Define if your libraries define daemon() */
#undef HAVE_DAEMON

/* Define if your libraries define getpagesize() */
#undef HAVE_GETPAGESIZE

/* Define if xauth is found in your path */
#undef XAUTH_PATH

/* Define if rsh is found in your path */
#undef RSH_PATH

/* Define if you want to allow MD5 passwords */
#undef HAVE_MD5_PASSWORDS

/* Define if you want to disable shadow passwords */
#undef DISABLE_SHADOW

/* Define if you want to use shadow password expire field */
#undef HAS_SHADOW_EXPIRE

/* Define if you want have trusted HPUX */
#undef HAVE_HPUX_TRUSTED_SYSTEM_PW

/* Define if you have Digital Unix Security Integration Architecture */
#undef HAVE_OSF_SIA

/* Define if you have getpwanam(3) [SunOS 4.x] */
#undef HAVE_GETPWANAM

/* Defined if in_systm.h needs to be included with netinet/ip.h (HPUX - <sigh/>) */
#undef NEED_IN_SYSTM_H

/* Define if you have an old version of PAM which takes only one argument */
/* to pam_strerror */
#undef HAVE_OLD_PAM

/* Set this to your mail directory if you don't have maillock.h */
#undef MAIL_DIRECTORY

/* Data types */
#undef HAVE_U_INT
#undef HAVE_INTXX_T
#undef HAVE_U_INTXX_T
#undef HAVE_UINTXX_T
#undef HAVE_SOCKLEN_T
#undef HAVE_SIZE_T
#undef HAVE_SSIZE_T
#undef HAVE_MODE_T
#undef HAVE_PID_T
#undef HAVE_SA_FAMILY_T
#undef HAVE_STRUCT_SOCKADDR_STORAGE
#undef HAVE_STRUCT_ADDRINFO
#undef HAVE_STRUCT_IN6_ADDR
#undef HAVE_STRUCT_SOCKADDR_IN6

/* Fields in struct sockaddr_storage */
#undef HAVE_SS_FAMILY_IN_SS
#undef HAVE___SS_FAMILY_IN_SS

/* Define if you have /dev/ptmx */
#undef HAVE_DEV_PTMX

/* Define if you have /dev/ptc */
#undef HAVE_DEV_PTS_AND_PTC

/* Define if you need to use IP address instead of hostname in $DISPLAY */
#undef IPADDR_IN_DISPLAY

/* Specify default $PATH */
#undef USER_PATH

/* Specify location of ssh.pid */
#undef PIDDIR

/* Use IPv4 for connection by default, IPv6 can still if explicity asked */
#undef IPV4_DEFAULT

/* getaddrinfo is broken (if present) */
#undef BROKEN_GETADDRINFO

/* Workaround more Linux IPv6 quirks */
#undef DONT_TRY_OTHER_AF

/* Detect IPv4 in IPv6 mapped addresses and treat as IPv4 */
#undef IPV4_IN_IPV6

@BOTTOM@

/* ******************* Shouldn't need to edit below this line ************** */

#include "defines.h"

#endif /* _CONFIG_H */
