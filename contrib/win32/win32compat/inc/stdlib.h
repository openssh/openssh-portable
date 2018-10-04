#include "crtheaders.h"
#include STDLIB_H

#define environ _environ
void freezero(void *, size_t);
int setenv(const char *name, const char *value, int rewrite);
