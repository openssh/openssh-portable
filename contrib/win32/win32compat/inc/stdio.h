#include "crtheaders.h"
#include STDIO_H

/* stdio.h overrides */
#define fopen w32_fopen_utf8

/* stdio.h additional definitions */
#define popen _popen
#define pclose _pclose