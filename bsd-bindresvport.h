#ifndef _BSD_BINRESVPORT_H
#define _BSD_BINRESVPORT_H

#include "config.h"

#ifndef HAVE_BINRESVPORT_AF
int bindresvport_af(int sd, struct sockaddr *sa, int af);
#endif /* !HAVE_BINRESVPORT_AF */

#endif /* _BSD_BINRESVPORT_H */
