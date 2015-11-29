/* Placed in the public domain.  */

#include "includes.h"

#ifndef HAVE_PLEDGE

/* Stub; real implementations wanted. */
int
pledge(const char *promises, const char *paths[])
{
	return 0;
}

#endif /* HAVE_PLEDGE */
