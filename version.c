#include "version.h"

#include <stdio.h>
#include <string.h>

#ifdef WITH_ZLIB
#include <zlib.h>
#define ZLIB_VERSION_MAX_SIZE 30
#endif /* WITH_ZLIB */

void print_ssh_version(void) {
#ifdef WITH_ZLIB
	const char ssh_zlib_version[ZLIB_VERSION_MAX_SIZE] = "zlib ";
	strncat(ssh_zlib_version, zlibVersion(), ZLIB_VERSION_MAX_SIZE - strlen(ssh_zlib_version));
#else /* WITH_ZLIB */
	const char* ssh_zlib_version = "without zlib";
#endif /* WITH_ZLIB */

	fprintf(stderr, "%s, %s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION, ssh_zlib_version);
}
