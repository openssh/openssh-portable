/* RCSID("$Id: nchan.h,v 1.1 1999/10/27 03:42:44 damien Exp $"); */

#ifndef NCHAN_H
#define NCHAN_H

/*
 * SSH Protocol 1.5 aka New Channel Protocol
 * Thanks to Martina, Axel and everyone who left Erlangen, leaving me bored.
 * Written by Markus Friedl in October 1999
 * 
 * Protocol versions 1.3 and 1.5 differ in the handshake protocol used for the
 * tear down of channels:
 * 
 * 1.3:	strict request-ack-protocol:
 * 	CLOSE	->
 * 		<-  CLOSE_CONFIRM
 * 
 * 1.5:	uses variations of:
 * 	IEOF	->
 * 		<-  OCLOSE
 * 		<-  IEOF
 * 	OCLOSE	->
 * 	i.e. both sides have to close the channel
 * 
 * See the debugging output from 'ssh -v' and 'sshd -d' of
 * ssh-1.2.27 as an example.
 * 
 */

/* ssh-proto-1.5 overloads prot-1.3-message-types */
#define SSH_MSG_CHANNEL_INPUT_EOF	SSH_MSG_CHANNEL_CLOSE
#define SSH_MSG_CHANNEL_OUTPUT_CLOSE	SSH_MSG_CHANNEL_CLOSE_CONFIRMATION

/* possible input states */
#define CHAN_INPUT_OPEN			0x01
#define CHAN_INPUT_WAIT_DRAIN		0x02
#define CHAN_INPUT_WAIT_OCLOSE		0x04
#define CHAN_INPUT_CLOSED		0x08

/* possible output states */
#define CHAN_OUTPUT_OPEN		0x10
#define CHAN_OUTPUT_WAIT_DRAIN		0x20
#define CHAN_OUTPUT_WAIT_IEOF		0x40
#define CHAN_OUTPUT_CLOSED		0x80

/* EVENTS for the input state */
void chan_rcvd_oclose(Channel *c);
void chan_read_failed(Channel *c);
void chan_ibuf_empty(Channel *c);

/* EVENTS for the output state */
void chan_rcvd_ieof(Channel *c);
void chan_write_failed(Channel *c);
void chan_obuf_empty(Channel *c);

void chan_init_iostates(Channel *c);
#endif
