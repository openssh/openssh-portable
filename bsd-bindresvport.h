#ifndef _BSD_BINDRESVPORT_H
#define _BSD_BINDRESVPORT_H

#include "config.h"

#ifndef HAVE_BINDRESVPORT_SA
int bindresvport_sa(int sd, struct sockaddr *sa);
#endif /* !HAVE_BINDRESVPORT_SA */

#endif /* _BSD_BINDRESVPORT_H */
