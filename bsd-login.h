#ifndef _BSD_LOGIN_H
# define _BSD_LOGIN_H

# include "config.h"
# ifndef HAVE_LOGIN

#  include <utmp.h>

#  if defined(HAVE_UTMPX_H) && defined(USE_UTMPX)
#   include <utmpx.h>

void login(struct utmp *utp, struct utmpx *utx);

#   else /* defined(HAVE_UTMPX_H) && defined(USE_UTMPX) */

void login(struct utmp *utp);

#  endif /* defined(HAVE_UTMPX_H) && defined(USE_UTMPX) */

# endif /* !HAVE_LOGIN */

#endif /* _BSD_LOGIN_H */
