#ifndef _OPENBSD_H
#define _OPENBSD_H

#include "config.h"

/* BSD function replacements */
#include "bsd-bindresvport.h"
#include "bsd-rresvport.h"
#include "bsd-misc.h"
#include "bsd-strlcpy.h"
#include "bsd-strlcat.h"
#include "bsd-mktemp.h"
#include "bsd-snprintf.h"
#include "bsd-daemon.h"
#include "bsd-base64.h"

/* rfc2553 socket API replacements */
#include "fake-getaddrinfo.h"
#include "fake-getnameinfo.h"
#include "fake-socket.h"

#endif /* _OPENBSD_H */
