/* Generated automatically from acconfig.h by autoheader. */
/* Please make your changes there */

@TOP@

/* SSL directory.  */
#undef ssldir

/* Define if you want to disable PAM support */
#undef DISABLE_PAM

/* Define if you want to disable lastlog support */
#undef DISABLE_LASTLOG

/* Location of lastlog file */
#undef LASTLOG_LOCATION

/* If lastlog is a directory */
#undef LASTLOG_IS_DIR

/* Location of random number pool  */
#undef RANDOM_POOL

/* Are we using the Entropy gathering daemon */
#undef HAVE_EGD

/* Define if your ssl headers are included with #include <ssl/header.h>  */
#undef HAVE_SSL

/* Define if your ssl headers are included with #include <openssl/header.h>  */
#undef HAVE_OPENSSL

/* Define is utmp.h has a ut_host field */
#undef HAVE_HOST_IN_UTMP

/* Define is utmpx.h has a ut_host field */
#undef HAVE_HOST_IN_UTMPX

/* Define is utmpx.h has a syslen field */
#undef HAVE_SYSLEN_IN_UTMPX

/* Define is utmp.h has a ut_pid field */
#undef HAVE_PID_IN_UTMP

/* Define is utmp.h has a ut_type field */
#undef HAVE_TYPE_IN_UTMP

/* Define is utmp.h has a ut_tv field */
#undef HAVE_TV_IN_UTMP

/* Define if you want to use utmpx */
#undef USE_UTMPX

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

/* Define if xauth is found in your path */
#undef XAUTH_PATH

/* Define if rsh is found in your path */
#undef RSH_PATH

/* Define if you want to allow MD5 passwords */
#undef HAVE_MD5_PASSWORDS

/* Define if you want to disable shadow passwords */
#undef DISABLE_SHADOW

/* Define if you want have trusted HPUX */
#undef HAVE_HPUX_TRUSTED_SYSTEM_PW

/* Define if you have an old version of PAM which takes only one argument */
/* to pam_strerror */
#undef HAVE_OLD_PAM

/* Set this to your mail directory if you don't have maillock.h */
#undef MAIL_DIRECTORY

/* Data types */
#undef HAVE_QUAD_T
#undef HAVE_INTXX_T
#undef HAVE_U_INTXX_T
#undef HAVE_UINTXX_T
#undef HAVE_SOCKLEN_T

/* Define if you have /dev/ptmx */
#undef HAVE_DEV_PTMX

/* Define if you have /dev/ptc */
#undef HAVE_DEV_PTS_AND_PTC

/* Define if you need to use IP address instead of hostname in $DISPLAY */
#undef IPADDR_IN_DISPLAY

/* Specify default $PATH */
#undef USER_PATH

/* Define if the inclusion of crypt.h breaks the build (e.g. Irix 5.x) */
#undef CRYPT_H_BREAKS_BUILD

@BOTTOM@

/* ******************* Shouldn't need to edit below this line ************** */

#include "defines.h"
