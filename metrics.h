#ifndef METRICS_H
#define METRICS_H

#include "binn.h"
#include <linux/tcp.h>

void metrics_write_binn_object(struct tcp_info *, struct binn_struct *);
void metrics_read_binn_object(void *, char **);
void metrics_print_header(FILE *, char *);


#endif /* define metrics_h */
