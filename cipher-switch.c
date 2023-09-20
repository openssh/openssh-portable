/*
 * Copyright (c) 2023 The Board of Trustees of Carnegie Mellon University.
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

/* This provides the function to switch from a serial to parallel
 * cipher. This has been moved into it's own file in order to make it
 * available to both the client and server without having to clutter
 * up other files.
 */

#include "includes.h"
#include <sys/types.h>
#include <string.h>
#include "cipher.h"
#include "log.h"
#include "packet.h"


/* if we are using a parallel cipher there can be issues in either
 * a fork or sandbox. Essentially, if we switch too early the
 * threads get lost and the application hangs. So what we do is
 * test if either the send or receive context cipher name
 * matches the known available parallel ciphers. If it does
 * then we force a rekey which automatically loads the parallel
 * cipher. */

void
cipher_switch(struct ssh *ssh) {
#ifdef WITH_OPENSSL
	/* get the send and receive context and extract the cipher name */
	const void *send_cc = ssh_packet_get_send_context(ssh);
	const void *recv_cc = ssh_packet_get_receive_context(ssh);
	const char *send = cipher_ctx_name(send_cc);
	const char *recv = cipher_ctx_name(recv_cc);

	debug_f("Send: %s Recv: %s", send, recv);
	
	/* if the name of the cipher matches then we set the context
	 * to authenticated (it likely already is though) and then
	 * force the rekey. Either side can do this. One downside of
	 * this method is that both sides can request a rekey so you
	 * can end up duplicating work. This is annoying but the
	 * performance gains make it worthwhile. Also I
	 * use strstr here because strcmp would require a 6 part
	 * if statement */
	if (strstr(send, "ctr") || strstr(recv, "ctr")) {
		debug("Serial to parallel AES-CTR cipher swap");
		/* cipher_reset_multithreaded(); */
		ssh_packet_set_authenticated(ssh);
		packet_request_rekeying();
	}
	/* do the same for multithreaded chacha20 but with strcmp */
	if ((strcmp(send, "chacha20-poly1305@openssh.com") == 0) ||
	    (strcmp(recv, "chacha20-poly1305@openssh.com") == 0)) {
		debug("Serial to parallel Chacha20-poly1305 cipher swap");
		ssh_packet_set_authenticated(ssh);
		packet_request_rekeying();
	}
#endif
}
