#ifndef _PAL_DOEXEC_H
#define _PAL_DOEXEC_H

#include "session.h"

int	do_exec_pty(struct ssh *, Session *, const char *);
int	do_exec_no_pty(struct ssh *, Session *, const char *);
#endif /* _PAL_DOEXEC_H */