/* $OpenBSD: ssh-sk-helper.c,v 1.1 2019/10/31 21:22:01 djm Exp $ */
/*
 * Copyright (c) 2019 Google LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This is a tiny program used to isolate the address space used for
 * security key middleware signing operations from ssh-agent. It is similar
 * to ssh-pkcs11-helper.c but considerably simpler as the signing operation
 * for this case are stateless.
 *
 * It receives a signing request (key, provider, message, flags) from
 * stdin, attempts to perform a signature using the security key provider
 * and returns the resultant signature via stdout.
 *
 * In the future, this program might gain additional functions to support
 * FIDO2 tokens such as enumerating resident keys. When this happens it will
 * be necessary to crank SSH_SK_HELPER_VERSION below.
 */

#include "includes.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "xmalloc.h"
#include "log.h"
#include "sshkey.h"
#include "authfd.h"
#include "misc.h"
#include "sshbuf.h"
#include "msg.h"
#include "uidswap.h"
#include "sshkey.h"
#include "ssherr.h"
#include "ssh-sk.h"

#ifdef ENABLE_SK
extern char *__progname;

int
main(int argc, char **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	struct sshbuf *req, *resp, *kbuf;
	struct sshkey *key;
	uint32_t compat;
	const u_char *message;
	u_char version, *sig;
	size_t msglen, siglen;
	char *provider;
	int in, out, ch, r, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			log_stderr = 1;
			if (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			else if (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			break;
		default:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			exit(1);
		}
	}
	log_init(__progname, log_level, log_facility, log_stderr);

	/*
	 * Rearrange our file descriptors a little; we don't trust the
	 * providers not to fiddle with stdin/out.
	 */
	closefrom(STDERR_FILENO + 1);
	if ((in = dup(STDIN_FILENO)) == -1 || (out = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	if ((req = sshbuf_new()) == NULL || (resp = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __progname);
	if (ssh_msg_recv(in, req) < 0)
		fatal("ssh_msg_recv failed");
	close(in);
	debug("%s: received message len %zu", __progname, sshbuf_len(req));

	if ((r = sshbuf_get_u8(req, &version)) != 0)
		fatal("%s: buffer error: %s", __progname, ssh_err(r));
	if (version != SSH_SK_HELPER_VERSION) {
		fatal("unsupported version: received %d, expected %d",
		    version, SSH_SK_HELPER_VERSION);
	}
	if ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshkey_private_deserialize(kbuf, &key)) != 0)
		fatal("Unable to parse key: %s", ssh_err(r));
	if (sshkey_type_plain(key->type) != KEY_ECDSA_SK)
		fatal("Unsupported key type %s", sshkey_ssh_name(key));

	if ((r = sshbuf_get_cstring(req, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(req, &message, &msglen)) != 0 ||
	    (r = sshbuf_get_u32(req, &compat)) != 0)
		fatal("%s: buffer error: %s", __progname, ssh_err(r));
	if (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	debug("%s: ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", __progname, sshkey_type(key),
	    provider, msglen, (u_long)compat);

	if ((r = sshsk_ecdsa_sign(provider, key, &sig, &siglen,
	    message, msglen, compat)) != 0)
		fatal("Signing failed: %s", ssh_err(r));

	/* send reply */
	if ((r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal("%s: buffer error: %s", __progname, ssh_err(r));
	debug("%s: reply len %zu", __progname, sshbuf_len(resp));
	if (ssh_msg_send(out, SSH_SK_HELPER_VERSION, resp) == -1)
		fatal("ssh_msg_send failed");
	close(out);

	return (0);
}
#else /* ENABLE_SK */
#include <stdio.h>

int
main(int argc, char **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	return -1;
}
#endif /* ENABLE_SK */
