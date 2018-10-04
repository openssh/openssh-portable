#define __STDC__ 1
#include "..\crtheaders.h"
#include SYS_TYPES_H

typedef _dev_t dev_t;
typedef long long off_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;

typedef unsigned short _mode_t;
typedef _mode_t mode_t;
typedef int ssize_t;
typedef int pid_t;

typedef unsigned int	nfds_t;

/* copied from Windows SDK corecrt_wstdio.h to accomodate FILE definition via types.h in Unix */
#ifndef _FILE_DEFINED
#define _FILE_DEFINED
typedef struct _iobuf
{
	void* _Placeholder;
} FILE;
#endif
