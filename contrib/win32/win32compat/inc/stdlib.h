#include "crtheaders.h"
#include STDLIB_H

#define environ _environ
void freezero(void *, size_t);
int setenv(const char *name, const char *value, int rewrite);
#define system w32_system
int w32_system(const char *command);
char* realpath(const char *pathname, char *resolved);
