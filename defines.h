/* Necessary headers */

#include <sys/types.h> /* For u_intXX_t */
#include <sys/socket.h> /* For SHUT_XXXX */

#ifdef HAVE_PATHS_H
# include <paths.h> /* For _PATH_XXX */
#endif 

#ifdef HAVE_UTMP_H
# include <utmp.h> /* For _PATH_XXX */
#endif 

#if defined(HAVE_UTMPX_H) && defined(USE_UTMPX)
# include <utmpx.h> /* For _PATH_XXX */
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

/* Types */

/* If sys/types.h does not supply intXX_t, supply them ourselves */
/* (or die trying) */
#ifndef HAVE_INTXX_T
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
# if (SIZEOF_LONG_INT == 8)
typedef long int int64_t;
# else
#  if (SIZEOF_LONG_LONG_INT == 8)
typedef long long int int64_t;
#  else
#   error "64 bit int type not found."
#  endif
# endif
#endif

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#ifndef HAVE_U_INTXX_T
# ifdef HAVE_UINTXX_T
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef  uint64_t u_int64_t;
# else
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
#  if (SIZEOF_LONG_INT == 8)
typedef unsigned long int u_int64_t;
#  else
#   if (SIZEOF_LONG_LONG_INT == 8)
typedef unsigned long long int u_int64_t;
#   else
#    error "64 bit int type not found."
#   endif
#  endif
# endif
#endif

/* If quad_t is not supplied, then supply it now. We can rely on int64_t */
/* being defined by the above */
#ifndef HAVE_QUAD_T
typedef int64_t quad_t;
#endif

#ifndef HAVE_SOCKLEN_T
typedef unsigned int socklen_t;
#endif /* HAVE_SOCKLEN_T */

#ifndef HAVE_SIZE_T
typedef unsigned int size_t;
#endif /* HAVE_SIZE_T */

/* Paths */

/* If _PATH_LASTLOG is not defined by system headers, set it to the */
/* lastlog file detected by autoconf */
#ifndef _PATH_LASTLOG
# ifdef LASTLOG_LOCATION
#  define _PATH_LASTLOG LASTLOG_LOCATION
# endif
#endif

#ifndef _PATH_UTMP
# ifdef UTMP_FILE
#  define _PATH_UTMP UTMP_FILE
# else
#  define _PATH_UTMP "/var/adm/utmp"
# endif
#endif

#ifndef _PATH_WTMP
# ifdef WTMP_FILE
#  define _PATH_WTMP WTMP_FILE
# else
#  define _PATH_WTMP "/var/adm/wtmp"
# endif
#endif

#if defined(HAVE_UTMPX_H) && defined(USE_UTMPX)
# ifndef _PATH_UTMPX
#  ifdef UTMPX_FILE
#   define _PATH_UTMPX UTMPX_FILE
#  else
#   define _PATH_UTMPX "/var/adm/utmpx"
#  endif
# endif
# ifndef _PATH_WTMPX
#  ifdef WTMPX_FILE
#   define _PATH_WTMPX WTMPX_FILE
#  else
#   define _PATH_WTMPX "/var/adm/wtmp"
#  endif
# endif
#endif

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

/* Macros */

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

#if !defined(__GNUC__) || (__GNUC__ < 2)
#  define __attribute__(x)
#endif /* !defined(__GNUC__) || (__GNUC__ < 2) */

#if defined(HAVE_SECURITY_PAM_APPL_H) && !defined(DISABLE_PAM)
# define USE_PAM
#endif /* defined(HAVE_SECURITY_PAM_APPL_H) && !defined(DISABLE_PAM) */

/* Function replacement / compatibility hacks */

/* In older versions of libpam, pam_strerror takes a single argument */
#ifdef HAVE_OLD_PAM
# define PAM_STRERROR(a,b) pam_strerror((b))
#else
# define PAM_STRERROR(a,b) pam_strerror((a),(b))
#endif

