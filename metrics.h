/*
 * Copyright (c) 2022 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the MIT License for more details.
 *
 * You should have received a copy of the MIT License along with this library;
 * if not, see http://opensource.org/licenses/MIT.
 *
 */

#ifndef METRICS_H
#define METRICS_H

#include "binn.h"

/* linux, freebsd, and netbsd have tcp_info structs.
 * I don't know about other systems so we disable this
 * functionality for them */
#if defined __linux__ || defined __FreeBSD__ || defined __NetBSD__ && !defined(__alpine__)
#define TCP_INFO 1
#if defined __linux__ && !defined(__alpine__)
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
void metrics_read_binn_object(void *, char *);
void metrics_print_header(FILE *, char *, int);


#endif /* define metrics_h */
