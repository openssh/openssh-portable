#ifndef _MKTEMP_H
#define _MKTEMP_H
int mkstemps(char *path, int slen);
int mkstemp(char *path);
char *mkdtemp(char *path);

#endif /* _MKTEMP_H */
