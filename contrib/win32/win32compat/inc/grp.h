#ifndef COMPAT_GRP_H
#define COMPAT_GRP_H 1
#include <Windows.h>
#include "sys/types.h"

char ** getusergroups(const char *user, int *numgroups);

#endif
