/* $OpenBSD: version.h,v 1.105 2025/04/09 07:00:21 djm Exp $ */

#ifndef VERSION_H
#define VERSION_H

#define SSH_VERSION	"OpenSSH_10.0"

#define SSH_PORTABLE	"p2"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE


#include "includes.h"

#ifdef WITH_OPENSSL
#include <openssl/rsa.h>
#define SSH_OPENSSL_VERSION OpenSSL_version(OPENSSL_VERSION)
#else /* WITH_OPENSSL */
#define SSH_OPENSSL_VERSION "without OpenSSL"
#endif /* WITH_OPENSSL */

void print_ssh_version(void);

#endif /* VERSION_H */
