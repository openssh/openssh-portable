#ifndef _DEFINES_H
#define _DEFINES_H

/* Necessary headers */

#include <sys/types.h> /* For [u]intxx_t */
#include <sys/socket.h> /* For SHUT_XXXX */
#include <sys/param.h> /* For MAXPATHLEN */
#include <sys/un.h> /* For SUN_LEN */
#include <netinet/in_systm.h> /* For typedefs */
#include <netinet/in.h> /* For IPv6 macros */
#include <netinet/ip.h> /* For IPTOS macros */
#ifdef HAVE_SYS_BITYPES_H
# include <sys/bitypes.h> /* For u_intXX_t */
#endif 
#ifdef HAVE_PATHS_H
# include <paths.h> /* For _PATH_XXX */
#endif 
#ifdef HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX */
#endif 
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h> /* For timersub */
#endif
#ifdef HAVE_MAILLOCK_H
# include <maillock.h> /* For _PATH_MAILDIR */
#endif
#ifdef HAVE_SYS_CDEFS_H
# include <sys/cdefs.h> /* For __P() */
#endif 
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h> /* For MIN, MAX, etc */
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h> /* For S_* constants and macros */
#endif

#include <unistd.h> /* For STDIN_FILENO, etc */

/* Constants */

#ifndef SHUT_RDWR
enum
{
  SHUT_RD = 0,		/* No more receptions.  */
  SHUT_WR,			/* No more transmissions.  */
  SHUT_RDWR			/* No more receptions or transmissions.  */
};
# define SHUT_RD   SHUT_RD
# define SHUT_WR   SHUT_WR
# define SHUT_RDWR SHUT_RDWR
#endif

#ifndef IPTOS_LOWDELAY
# define IPTOS_LOWDELAY          0x10
# define IPTOS_THROUGHPUT        0x08
# define IPTOS_RELIABILITY       0x04
# define IPTOS_LOWCOST           0x02
# define IPTOS_MINCOST           IPTOS_LOWCOST
#endif /* IPTOS_LOWDELAY */

#ifndef MAXPATHLEN
# ifdef PATH_MAX
#  define MAXPATHLEN PATH_MAX
# else /* PATH_MAX */
#  define MAXPATHLEN 64 /* Should be safe */
# endif /* PATH_MAX */
#endif /* MAXPATHLEN */

#ifndef STDIN_FILENO     
# define STDIN_FILENO    0
#endif                   
#ifndef STDOUT_FILENO    
# define STDOUT_FILENO   1
#endif                   
#ifndef STDERR_FILENO    
# define STDERR_FILENO   2
#endif                   

#ifndef S_ISREG
# define S_ISDIR(mode)	(((mode) & (_S_IFMT)) == (_S_IFDIR))
# define S_ISREG(mode)	(((mode) & (_S_IFMT)) == (_S_IFREG))
#endif /* S_ISREG */

#ifndef S_IXUSR
# define S_IXUSR			0000100	/* execute/search permission, */
# define S_IXGRP			0000010	/* execute/search permission, */
# define S_IXOTH			0000001	/* execute/search permission, */
# define _S_IWUSR			0000200	/* write permission, */
# define S_IWUSR			_S_IWUSR	/* write permission, owner */
# define S_IWGRP			0000020	/* write permission, group */
# define S_IWOTH			0000002	/* write permission, other */
# define S_IRUSR			0000400	/* read permission, owner */
# define S_IRGRP			0000040	/* read permission, group */
# define S_IROTH			0000004	/* read permission, other */
# define S_IRWXU			0000700	/* read, write, execute */
# define S_IRWXG			0000070	/* read, write, execute */
# define S_IRWXO			0000007	/* read, write, execute */
#endif /* S_IXUSR */

/* Types */

/* If sys/types.h does not supply intXX_t, supply them ourselves */
/* (or die trying) */

#ifndef HAVE_U_INT
typedef unsigned int u_int;
#endif

#ifndef HAVE_INTXX_T
# if (SIZEOF_CHAR == 1)
typedef char int8_t;
# else
#  error "8 bit int type not found."
# endif
# if (SIZEOF_SHORT_INT == 2)
typedef short int int16_t;
# else
#  error "16 bit int type not found."
# endif
# if (SIZEOF_INT == 4)
typedef int int32_t;
# else
#  error "32 bit int type not found."
# endif
/*
# if (SIZEOF_LONG_INT == 8)
typedef long int int64_t;
# else
#  if (SIZEOF_LONG_LONG_INT == 8)
typedef long long int int64_t;
#   define HAVE_INTXX_T 1
#  else
#   error "64 bit int type not found."
#  endif
# endif
*/
#endif

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#ifndef HAVE_U_INTXX_T
# ifdef HAVE_UINTXX_T
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
/*
typedef  uint64_t u_int64_t;
*/
# define HAVE_U_INTXX_T 1
# else
#  if (SIZEOF_CHAR == 1)
typedef unsigned char u_int8_t;
#  else
#   error "8 bit int type not found."
#  endif
#  if (SIZEOF_SHORT_INT == 2)
typedef unsigned short int u_int16_t;
#  else
#   error "16 bit int type not found."
#  endif
#  if (SIZEOF_INT == 4)
typedef unsigned int u_int32_t;
#  else
#   error "32 bit int type not found."
#  endif
/*
#  if (SIZEOF_LONG_INT == 8)
typedef unsigned long int u_int64_t;
#  else
#   if (SIZEOF_LONG_LONG_INT == 8)
typedef unsigned long long int u_int64_t;
#    define HAVE_U_INTXX_T 1
#   else
#    error "64 bit int type not found."
#   endif
#  endif
*/
# endif
#endif

#ifndef HAVE_SOCKLEN_T
typedef unsigned int socklen_t;
# define HAVE_SOCKLEN_T
#endif /* HAVE_SOCKLEN_T */

#ifndef HAVE_SIZE_T
typedef unsigned int size_t;
# define HAVE_SIZE_T
#endif /* HAVE_SIZE_T */

#ifndef HAVE_SSIZE_T
typedef int ssize_t;
# define HAVE_SSIZE_T
#endif /* HAVE_SSIZE_T */

#ifndef HAVE_SA_FAMILY_T
typedef int sa_family_t;
# define HAVE_SA_FAMILY_T
#endif /* HAVE_SA_FAMILY_T */

#ifndef HAVE_PID_T
typedef int pid_t;
# define HAVE_PID_T
#endif /* HAVE_PID_T */

#ifndef HAVE_MODE_T
typedef int mode_t;
# define HAVE_MODE_T
#endif /* HAVE_MODE_T */

#if !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE___SS_FAMILY_IN_SS)
# define ss_family __ss_family
#endif /* !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE_SA_FAMILY_IN_SS) */

/* Paths */

#ifndef _PATH_BSHELL
# define _PATH_BSHELL "/bin/sh"
#endif

#ifdef USER_PATH
# ifdef _PATH_STDPATH
#  undef _PATH_STDPATH
# endif
# define _PATH_STDPATH USER_PATH
#endif

#ifndef _PATH_STDPATH
# define _PATH_STDPATH "/usr/bin:/bin:/usr/sbin:/sbin"
#endif

#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL "/dev/null"
#endif

#ifndef MAIL_DIRECTORY
# define MAIL_DIRECTORY "/var/spool/mail"
#endif

#ifndef MAILDIR
# define MAILDIR MAIL_DIRECTORY
#endif

#if !defined(_PATH_MAILDIR) && defined(MAILDIR)
# define _PATH_MAILDIR MAILDIR
#endif /* !defined(_PATH_MAILDIR) && defined(MAILDIR) */

#ifndef _PATH_RSH
# ifdef RSH_PATH
#  define _PATH_RSH RSH_PATH
# endif /* RSH_PATH */
#endif /* _PATH_RSH */

#ifndef _PATH_NOLOGIN
# define _PATH_NOLOGIN "/etc/nologin"
#endif

/* Macros */

#if defined(HAVE_LOGIN_GETCAPBOOL) && defined(HAVE_LOGIN_CAP_H)
# define HAVE_LOGIN_CAP
#endif

#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef timersub
#define timersub(a, b, result)										  \
   do {																		  \
      (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;           \
      (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;        \
      if ((result)->tv_usec < 0) {                            \
         --(result)->tv_sec;                                  \
         (result)->tv_usec += 1000000;                        \
      }                                                       \
   } while (0)
#endif

#ifndef __P
# define __P(x) x
#endif

#if !defined(IN6_IS_ADDR_V4MAPPED)
# define IN6_IS_ADDR_V4MAPPED(a) \
	((((u_int32_t *) (a))[0] == 0) && (((u_int32_t *) (a))[1] == 0) && \
	 (((u_int32_t *) (a))[2] == htonl (0xffff)))
#endif /* !defined(IN6_IS_ADDR_V4MAPPED) */

#if !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#endif /* !defined(__GNUC__) || (__GNUC__ < 2) */

#if defined(HAVE_SECURITY_PAM_APPL_H) && !defined(DISABLE_PAM)
# define USE_PAM
#endif /* defined(HAVE_SECURITY_PAM_APPL_H) && !defined(DISABLE_PAM) */

#ifndef SUN_LEN
#define SUN_LEN(su) \
        (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif /* SUN_LEN */

/* Function replacement / compatibility hacks */

/* In older versions of libpam, pam_strerror takes a single argument */
#ifdef HAVE_OLD_PAM
# define PAM_STRERROR(a,b) pam_strerror((b))
#else
# define PAM_STRERROR(a,b) pam_strerror((a),(b))
#endif

#if defined(BROKEN_GETADDRINFO) && defined(HAVE_GETADDRINFO)
# undef HAVE_GETADDRINFO
#endif /* defined(BROKEN_GETADDRINFO) && defined(HAVE_GETADDRINFO) */

#if !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY)
# define memmove(s1, s2, n) bcopy((s2), (s1), (n))
#endif /* !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY) */

#if !defined(HAVE_ATEXIT) && defined(HAVE_ON_EXIT)
# define atexit(a) on_exit(a)
#endif /* !defined(HAVE_ATEXIT) && defined(HAVE_ON_EXIT) */

/**
 ** login recorder definitions
 **/

/* preprocess */

#ifdef HAVE_UTMP_H
#  ifdef HAVE_TIME_IN_UTMP
#    include <time.h>
#  endif
#  include <utmp.h>
#endif
#ifdef HAVE_UTMPX_H
#  ifdef HAVE_TV_IN_UTMPX
#    include <sys/time.h>
#  endif
#  include <utmpx.h>
#endif
#ifdef HAVE_LASTLOG_H
#  include <lastlog.h>
#endif
#ifdef HAVE_PATHS_H
#  include <paths.h>
#endif

/* FIXME: put default paths back in */
#ifndef UTMP_FILE
#  ifdef _PATH_UTMP
#    define UTMP_FILE _PATH_UTMP
#  else
#    ifdef CONF_UTMP_FILE
#      define UTMP_FILE CONF_UTMP_FILE
#    endif
#  endif
#endif
#ifndef WTMP_FILE
#  ifdef _PATH_WTMP
#    define WTMP_FILE _PATH_WTMP
#  else
#    ifdef CONF_WTMP_FILE
#      define WTMP_FILE CONF_WTMP_FILE
#    endif
#  endif
#endif
/* pick up the user's location for lastlog if given */
#ifndef LASTLOG_FILE
#  ifdef _PATH_LASTLOG
#    define LASTLOG_FILE _PATH_LASTLOG
#  else
#    ifdef CONF_LASTLOG_FILE
#      define LASTLOG_FILE CONF_LASTLOG_FILE
#    endif
#  endif
#endif


/* The login() library function in libutil is first choice */
#if defined(HAVE_LOGIN) && !defined(DISABLE_LOGIN)
#  define USE_LOGIN

#else
/* Simply select your favourite login types. */
/* Can't do if-else because some systems use several... <sigh> */
#  if defined(UTMPX_FILE) && !defined(DISABLE_UTMPX)
#    define USE_UTMPX
#  endif
#  if defined(UTMP_FILE) && !defined(DISABLE_UTMP)
#    define USE_UTMP
#  endif
#  if defined(WTMPX_FILE) && !defined(DISABLE_WTMPX)
#    define USE_WTMPX
#  endif
#  if defined(WTMP_FILE) && !defined(DISABLE_WTMP)
#    define USE_WTMP
#  endif

#endif

/* I hope that the presence of LASTLOG_FILE is enough to detect this */
#if defined(LASTLOG_FILE) && !defined(DISABLE_LASTLOG)
#  define USE_LASTLOG
#endif

/* which type of time to use? (api.c) */
#ifdef HAVE_SYS_TIME_H
#  define USE_TIMEVAL
#endif

/** end of login recorder definitions */

#endif /* _DEFINES_H */
