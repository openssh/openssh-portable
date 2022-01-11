#ifndef METRICS_H
#define METRICS_H

#include "binn.h"

/* linux, freebsd, and netbsd have tcp_info structs.
 * I don't know about other systems so we disable this
 * functionality for them */
#if defined __linux__ || defined __FreeBSD__ || defined __NetBSD__
#define TCP_INFO 1
#if defined __linux__
#include <linux/tcp.h>
#else
#include <netinet/tcp.h>
#endif
#else
/* make a null struct for tcp_info on systems that don't support it*/
typedef struct tcp_info {
	void     *dummy;
} tcp_info;
#endif

void metrics_write_binn_object(struct tcp_info *, struct binn_struct *);
void metrics_read_binn_object(void *, char **);
void metrics_print_header(FILE *, char *, int);


#endif /* define metrics_h */
