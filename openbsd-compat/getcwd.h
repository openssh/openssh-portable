#ifndef _BSD_GETCWD_H 
#define _BSD_GETCWD_H
#include "config.h"

#if !defined(HAVE_GETCWD)

char *getcwd(char *pt, size_t size);

#endif /* !defined(HAVE_GETCWD) */
#endif /* _BSD_GETCWD_H */
