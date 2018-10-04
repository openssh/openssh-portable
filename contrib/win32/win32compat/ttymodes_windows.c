/*
 * SSH2 tty modes for Windows
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/******* TODO - integrate these changes into ttymodes.c ******/

#include "includes.h"

#include <sys/types.h>

#include <errno.h>
#include <string.h>
#include <termios.h>
#include <stdarg.h>

#include "packet.h"
#include "log.h"
#include "compat.h"
#include "sshbuf.h"
#include "ssherr.h"

#define TTY_OP_END		0
/*
 * uint32 (u_int) follows speed in SSH1 and SSH2
 */
#define TTY_OP_ISPEED_PROTO1	192
#define TTY_OP_OSPEED_PROTO1	193
#define TTY_OP_ISPEED_PROTO2	128
#define TTY_OP_OSPEED_PROTO2	129

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
void
ssh_tty_make_modes(struct ssh *ssh, int fd, struct termios *tiop)
{
	struct termios tio;
	struct sshbuf *buf;
	int r, baud, tty_op_ospeed, tty_op_ispeed;
	
	if ((buf = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	tio = *tiop;
	
	tty_op_ospeed = TTY_OP_OSPEED_PROTO2;
	tty_op_ispeed = TTY_OP_ISPEED_PROTO2;
	/* Store input and output baud rates. */
	baud = 9600;

	if ((r = sshbuf_put_u8(buf, tty_op_ospeed)) != 0 ||
	    (r = sshbuf_put_u32(buf, baud)) != 0 ||
	    (r = sshbuf_put_u8(buf, tty_op_ispeed)) != 0 ||
	    (r = sshbuf_put_u32(buf, baud)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

#define TTYCHAR(NAME, OP) \
	if ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal("%s: buffer error: %s", __func__, ssh_err(r)); \

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	if (OP == SSH_TTYMODE_IUTF8 && (datafellows & SSH_BUG_UTF8TTYMODE)) { \
		debug3("%s: SSH_BUG_UTF8TTYMODE", __func__); \
	} else if ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal("%s: buffer error: %s", __func__, ssh_err(r)); \

#undef TTYCHAR
#undef TTYMODE

end :
	    /* Mark end of mode data. */
	    if ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		    fatal("%s: packet error: %s", __func__, ssh_err(r));
	    sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
void
ssh_tty_parse_modes(struct ssh *ssh, int fd)
{
	struct sshbuf *buf;
	const u_char *data;
	u_char opcode;
	u_int baud, u;
	int r, failure = 0;
	size_t len;

	if ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal("%s: packet error: %s", __func__, ssh_err(r));
	if (len == 0)
		return;
	if ((buf = sshbuf_from(data, len)) == NULL) {
		error("%s: sshbuf_from failed", __func__);
		return;
	}

	while (sshbuf_len(buf) > 0) {
		if ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal("%s: packet error: %s", __func__, ssh_err(r));
		switch (opcode) {
		case TTY_OP_END:
			goto set;

		case TTY_OP_ISPEED_PROTO2:
			if ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal("%s: packet error: %s",
					__func__, ssh_err(r));
			break;

		case TTY_OP_OSPEED_PROTO2:
			if ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal("%s: packet error: %s",
					__func__, ssh_err(r));
			break;

#define TTYCHAR(NAME, OP) \
		case OP: \
			if ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal("%s: packet error: %s", __func__, \
				    ssh_err(r)); \
			tio.c_cc[NAME] = special_char_decode(u); \
			break;
#define TTYMODE(NAME, FIELD, OP) \
		case OP: \
			if ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal("%s: packet error: %s", __func__, \
				    ssh_err(r)); \
			if (u) \
				tio.FIELD |= NAME; \
			else \
				tio.FIELD &= ~NAME; \
			break;

#undef TTYCHAR
#undef TTYMODE

		default:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
				opcode, opcode);
			/*
			* SSH2:
			* Opcodes 1 to 159 are defined to have a uint32
			* argument.
			* Opcodes 160 to 255 are undefined and cause parsing
			* to stop.
			*/
			if (opcode > 0 && opcode < 160) {
				if ((r = sshbuf_get_u32(buf, NULL)) != 0)
					fatal("%s: packet error: %s", __func__,
						ssh_err(r));
				break;
			}
			else {
				logit("%s: unknown opcode %d", __func__,
					opcode);
				goto set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	if (len > 0) {
		logit("%s: %zu bytes left", __func__, len);
		return;		/* Don't process bytes passed */
	}
	if (failure == -1)
		return;		/* Packet parsed ok but tcgetattr() failed */

}
