#ifndef _BSD_LOGIN_H
#define _BSD_LOGIN_H

#include "config.h"
#ifndef HAVE_LOGIN

#include <utmp.h>

void login(struct utmp *utp);

#endif /* !HAVE_LOGIN */

#endif /* _BSD_LOGIN_H */
