#ifndef _BSD_BINDRESVPORT_H
#define _BSD_BINDRESVPORT_H

#include "config.h"

#ifndef HAVE_BINDRESVPORT_AF
int bindresvport_af(int sd, struct sockaddr *sa, int af);
#endif /* !HAVE_BINDRESVPORT_AF */

#endif /* _BSD_BINDRESVPORT_H */
