#include "includes.h"
RCSID("$Id: nchan.c,v 1.1 1999/10/27 03:42:44 damien Exp $");

#include "ssh.h"

#include "buffer.h"
#include "packet.h"
#include "channels.h"
#include "nchan.h"

static void chan_send_ieof(Channel *c);
static void chan_send_oclose(Channel *c);
static void chan_shutdown_write(Channel *c);
static void chan_shutdown_read(Channel *c);
static void chan_delele_if_full_closed(Channel *c);

/*
 * EVENTS: update channel input/output states
 *	   execute ACTIONS
 */
/* events concerning the INPUT from socket for channel (istate) */
void
chan_rcvd_oclose(Channel *c){
	switch(c->istate){
	case CHAN_INPUT_WAIT_OCLOSE:
		debug("channel %d: INPUT_WAIT_OCLOSE -> INPUT_CLOSED [rcvd OCLOSE]", c->self);
		c->istate=CHAN_INPUT_CLOSED;
		chan_delele_if_full_closed(c);
		break;
	case CHAN_INPUT_OPEN:
		debug("channel %d: INPUT_OPEN -> INPUT_CLOSED [rvcd OCLOSE, send IEOF]", c->self);
		chan_shutdown_read(c);
		chan_send_ieof(c);
		c->istate=CHAN_INPUT_CLOSED;
		chan_delele_if_full_closed(c);
		break;
	default:
		debug("protocol error: chan_rcvd_oclose %d for istate %d",c->self,c->istate);
		break;
	}
}
void
chan_read_failed(Channel *c){
	switch(c->istate){
	case CHAN_INPUT_OPEN:
		debug("channel %d: INPUT_OPEN -> INPUT_WAIT_DRAIN [read failed]", c->self);
		chan_shutdown_read(c);
		c->istate=CHAN_INPUT_WAIT_DRAIN;
		break;
	default:
		debug("internal error: we do not read, but chan_read_failed %d for istate %d",
			c->self,c->istate);
		break;
	}
}
void
chan_ibuf_empty(Channel *c){
	if(buffer_len(&c->input)){
		debug("internal error: chan_ibuf_empty %d for non empty buffer",c->self);
		return;
	}
	switch(c->istate){
	case CHAN_INPUT_WAIT_DRAIN:
		debug("channel %d: INPUT_WAIT_DRAIN -> INPUT_WAIT_OCLOSE [inbuf empty, send IEOF]", c->self);
		chan_send_ieof(c);
		c->istate=CHAN_INPUT_WAIT_OCLOSE;
		break;
	default:
		debug("internal error: chan_ibuf_empty %d for istate %d",c->self,c->istate);
		break;
	}
}
/* events concerning the OUTPUT from channel for socket (ostate) */
void
chan_rcvd_ieof(Channel *c){
	switch(c->ostate){
	case CHAN_OUTPUT_OPEN:
		debug("channel %d: OUTPUT_OPEN -> OUTPUT_WAIT_DRAIN [rvcd IEOF]", c->self);
		c->ostate=CHAN_OUTPUT_WAIT_DRAIN;
		break;
	case CHAN_OUTPUT_WAIT_IEOF:
		debug("channel %d: OUTPUT_WAIT_IEOF -> OUTPUT_CLOSED [rvcd IEOF]", c->self);
		c->ostate=CHAN_OUTPUT_CLOSED;
		chan_delele_if_full_closed(c);
		break;
	default:
		debug("protocol error: chan_rcvd_ieof %d for ostate %d", c->self,c->ostate);
		break;
	}
}
void
chan_write_failed(Channel *c){
	switch(c->ostate){
	case CHAN_OUTPUT_OPEN:
		debug("channel %d: OUTPUT_OPEN -> OUTPUT_WAIT_IEOF [write failed]", c->self);
		chan_send_oclose(c);
		c->ostate=CHAN_OUTPUT_WAIT_IEOF;
		break;
	case CHAN_OUTPUT_WAIT_DRAIN:
		debug("channel %d: OUTPUT_WAIT_DRAIN -> OUTPUT_CLOSED [write failed]", c->self);
		chan_send_oclose(c);
		c->ostate=CHAN_OUTPUT_CLOSED;
		chan_delele_if_full_closed(c);
		break;
	default:
		debug("internal error: chan_write_failed %d for ostate %d",c->self,c->ostate);
		break;
	}
}
void
chan_obuf_empty(Channel *c){
	if(buffer_len(&c->output)){
		debug("internal error: chan_obuf_empty %d for non empty buffer",c->self);
		return;
	}
	switch(c->ostate){
	case CHAN_OUTPUT_WAIT_DRAIN:
		debug("channel %d: OUTPUT_WAIT_DRAIN -> OUTPUT_CLOSED [obuf empty, send OCLOSE]", c->self);
		chan_send_oclose(c);
		c->ostate=CHAN_OUTPUT_CLOSED;
		chan_delele_if_full_closed(c);
		break;
	default:
		debug("internal error: chan_obuf_empty %d for ostate %d",c->self,c->ostate);
		break;
	}
}
/*
 * ACTIONS: should never update c->istate or c->ostate
 */
static void
chan_send_ieof(Channel *c){
	switch(c->istate){
	case CHAN_INPUT_OPEN:
	case CHAN_INPUT_WAIT_DRAIN:
		packet_start(SSH_MSG_CHANNEL_INPUT_EOF);
		packet_put_int(c->remote_id);
		packet_send();
		break;
	default:
		debug("internal error: channel %d: cannot send IEOF for istate %d",c->self,c->istate);
		break;
	}
}
static void
chan_send_oclose(Channel *c){
	switch(c->ostate){
	case CHAN_OUTPUT_OPEN:
	case CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(c);
		buffer_consume(&c->output, buffer_len(&c->output));
		packet_start(SSH_MSG_CHANNEL_OUTPUT_CLOSE);
		packet_put_int(c->remote_id);
		packet_send();
		break;
	default:
		debug("internal error: channel %d: cannot send OCLOSE for ostate %d",c->self,c->istate);
		break;
	}
}
/* helper */
static void
chan_shutdown_write(Channel *c){
	debug("channel %d: shutdown_write", c->self);
	if(shutdown(c->sock, SHUT_WR)<0)
		error("chan_shutdown_write failed for #%d/fd%d: %.100s",
			c->self, c->sock, strerror(errno));
}
static void
chan_shutdown_read(Channel *c){
	debug("channel %d: shutdown_read", c->self);
	if(shutdown(c->sock, SHUT_RD)<0)
		error("chan_shutdown_read failed for #%d/fd%d: %.100s",
			c->self, c->sock, strerror(errno));
}
static void
chan_delele_if_full_closed(Channel *c){
	if(c->istate==CHAN_INPUT_CLOSED && c->ostate==CHAN_OUTPUT_CLOSED){
		debug("channel %d: closing", c->self);
		channel_free(c->self);
	}
}
void
chan_init_iostates(Channel *c){
	c->ostate=CHAN_OUTPUT_OPEN;
	c->istate=CHAN_INPUT_OPEN;
}
