/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */

/*
 * Ported from FreeBSD to Linux, only minimal changes.  --marekm
 */

/*
 * Adapted from shadow-19990607 by Tudor Bosman, tudorb@jm.nu
 */

#ifndef _MD5CRYPT_H
#define _MD5CRYPT_H

#include "config.h"

#include <unistd.h>
#include <string.h>

#ifdef HAVE_OPENSSL
#include <openssl/md5.h>
#endif

#ifdef HAVE_SSL
#include <ssl/md5.h>
#endif

int is_md5_salt(const char *salt);
char *md5_crypt(const char *pw, const char *salt);

#endif /* MD5CRYPT_H */
