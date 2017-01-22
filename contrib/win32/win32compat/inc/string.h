#include "crtheaders.h"
#include STRING_H

/* string.h overrides */
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
char *w32_strerror(int);
#define strerror w32_strerror