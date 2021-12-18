/* $OpenBSD$ */
/*
 * Copyright (c) 2021 Mitchell Blank Jr <mitch@bodyfour.uk>
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

#include "includes.h"

#include <stdio.h>

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "ssh.h"
#include "agentfilter.h"
#include "authfd.h"
#include "channels.h"
#include "log.h"
#include "match.h"
#include "misc.h"
#include "readconf.h"
#include "sshbuf.h"
#include "sshkey.h"

/* import options */
extern Options options;

struct agent_filter_accepted_identity {
	TAILQ_ENTRY(agent_filter_accepted_identity) next;
	struct sshkey *key;
};

struct agent_filter_state {
	/*
	 * The agent protocol is fully synchronous. We enforce that in
	 * the filter as well -- we will fail if we receive a message
	 * out-of-turn. This simplifies the logic and avoids situations
	 * where our state could become confused.
	 */
	enum {
		AGENT_FILTER_CONNECTION_DEAD,
		BUILDING_REQUEST,
		BUILDING_RESPONSE
	} direction;
	struct sshbuf *packet;
	TAILQ_HEAD(idqueue, agent_filter_accepted_identity) idlist;
};

static struct agent_filter_state *
agent_filter_new(void)
{
	struct agent_filter_state *st;

	debug2_f("entering");
	st = xmalloc(sizeof(*st));
	st->direction = BUILDING_REQUEST;
	if ((st->packet = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	TAILQ_INIT(&st->idlist);
	return st;
}

/* ARGSUSED */
static void
agent_filter_cleanup(struct ssh *ssh, int cid, void *ctx)
{
	struct agent_filter_state *st = (struct agent_filter_state *) ctx;
	struct agent_filter_accepted_identity *id;

	debug2_f("entering");
	sshbuf_free(st->packet);
	while ((id = TAILQ_FIRST(&st->idlist)) != NULL) {
		TAILQ_REMOVE(&st->idlist, id, next);
		sshkey_free(id->key);
		freezero(id, sizeof(*id));
	}
	freezero(ctx, sizeof(*st));
}

static int
identity_was_previously_accepted(const struct agent_filter_state *st,
    const struct sshkey *key)
{
	const struct agent_filter_accepted_identity *id;

	TAILQ_FOREACH(id, &st->idlist, next)
		if (sshkey_equal(key, id->key))
			return 1;
	return 0;
}

/* Takes ownership of "key". */
static void
identity_add_accepted(struct agent_filter_state *st, struct sshkey *key)
{
	if (identity_was_previously_accepted(st, key)) {
		sshkey_free(key);
	} else {
		struct agent_filter_accepted_identity *id;
		id = xmalloc(sizeof(*id));
		id->key = key;
		TAILQ_INSERT_TAIL(&st->idlist, id, next);
	}
}

/*
 * Returns 1 if "pkt" contains a full agent request/response packet,
 * 0 if we still need more data. Returns -1 if the packet's length
 * has some error.
 */
static int
packet_is_complete(const struct sshbuf *pkt, size_t max_payload)
{
	const size_t cur_len = sshbuf_len(pkt);

	if (cur_len >= 5) {
		const u_int32_t expected_payload = PEEK_U32(sshbuf_ptr(pkt));
		if (expected_payload > max_payload) {
			error("Packet exchanged on forwarded agent channel "
			    "was too large (%u > %u)",
			    (unsigned int)expected_payload,
			    (unsigned int)max_payload);
			return -1;
		}
		if (cur_len - 4 >= expected_payload) {
			/*
			 * The agent protocol is synchronous request/response
			 * so if we have some of the next packet already
			 * something went wrong!
			 */
			if (cur_len - 4 > expected_payload) {
				error("More data exchanged on forwarded "
				    "agent channel than needed for "
				    "single packet (%u > %u)",
				    (unsigned int)(cur_len - 4),
				    (unsigned int)expected_payload);
				return -1;
			}
			return 1;
		}
	}
	return 0;
}

static u_char
packet_type(const struct sshbuf *pkt)
{
	/*
	 * This is only used after packet_is_complete() returns 1,
	 * so we always have at least 5 bytes of packet data.
	 */
	return sshbuf_ptr(pkt)[4];
}

static int
accept_sign_request(struct agent_filter_state *st)
{
	int answer;
	struct sshkey *key = NULL;
	debug3_f("entering");

	/*
	 * Remove the packet length and the SSH2_AGENTC_SIGN_REQUEST
	 * at the front.
	 */
	if ((answer = sshbuf_consume(st->packet, 5)) != 0)
		return 0; /* Shouldn't be possible! */
	if ((answer = sshkey_froms(st->packet, &key)) != 0) {
		error_r(answer, "Failed to parse SIGN_REQUEST "
		    "sent to forwarded agent");
		return 0;
	}

	if ((answer = identity_was_previously_accepted(st, key)) == 0) {
		error("SIGN_REQUEST sent to forwarded agent for an "
		    "identity that had we had not previously advertised "
		    "to this client");
	}
	sshkey_free(key);
	return answer;
}

/*
 * Decide if st->packet is an acceptable request to pass along to the agent.
 * Can destroy st->packet in the process: it's just a temporary copy.
 */
static int
accept_request_packet(struct agent_filter_state *st)
{
	const u_char type = packet_type(st->packet);

	/*
	 * We only care about the SSH_AGENTC_* message types that the
	 * modern ssh-agent.c's process_message() knows about:
	 */
	switch (type) {
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		return 1;
	case SSH2_AGENTC_SIGN_REQUEST:
		return accept_sign_request(st);
	case SSH_AGENTC_LOCK:
	case SSH_AGENTC_UNLOCK:
		if (options.forward_agent_filter_permit_locking)
			return 1;
		error("rejecting request to lock/unlock agent over "
		      "forwarded agent channel "
		      "(see ForwardAgentFilterPermitLocking option)");
		break;
	case SSH2_AGENTC_ADD_IDENTITY:
	case SSH2_AGENTC_ADD_ID_CONSTRAINED:
	case SSH2_AGENTC_REMOVE_IDENTITY:
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
	case SSH_AGENTC_ADD_SMARTCARD_KEY:
	case SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED:
	case SSH_AGENTC_REMOVE_SMARTCARD_KEY:
		if (options.forward_agent_filter_permit_identity_management)
			return 1;
		error("rejecting request to add/remove identities over "
		    "forwarded agent channel "
		    "(see ForwardAgentFilterPermitIdentityManagement option)");
		break;
	default:
		error("rejecting unsuported command type 0x%02X over "
		     "forwarded agent channel", (unsigned int)type);
		break;
	}
	return 0;
}

/*
 * This receives traffic FROM the remote side (i.e. ssh agent requests).
 * This acts similar to process_message() in ssh-agent.c.
 *
 * The channel_register_filter() callback API is pretty subtle, so be careful:
 *
 * * On entry, c->output contains the data we've received from the client.
 *   Effectively it is a requirement that on exit c->output contains the
 *   data as well: the flow control code tracks any decrease in the size
 *   of c->output to be what is "locally consumed", so if you don't use
 *   c->output for this purpose that will break.
 *
 * * In particular, this means that you can't *grow* the size of the
 *   data or the flow control code won't know how to deal with it
 *   (it would mean c->local_consumed would become negative)  Unfortunately
 *   this precludes a simple implementation where we accumulate a request
 *   packet, decide its fate, and then pass it on: if the packet arrives
 *   in two chunks the second filter call would need to return more data
 *   than it had been passed!
 *
 * * If NULL is returned, the channel will be killed.
 *
 * * Otherwise, you must return a pointer to the data and its size in *dlen
 *   As noted above, this basically just has to point to c->output or there
 *   will be problems.
 *
 * * Finally, *data should also be populated with this pointer, although
 *   that is actually only used for datagram channels.
 *
 * Although this limited API complicates our task a bit, the situation can be
 * salvaged. Normally, we always pass request data through the channel
 * unchanged. Separately we build our own st->packet object containing
 * each request and pass judgement on it. If we decide a request shouldn't
 * pass, we simply kill the channel. This means that (at worst) ssh-agent
 * will see the first part of a request, but that won't cause any harm since
 * it operates on full request packets only.
 *
 * The one unfortunate effect is that there isn't any clean way to make
 * calls like SSH2_AGENTC_ADD_{IDENTITY,ID_CONSTRAINED} just become no-ops
 * so using AddKeysToAgent on a connection that doesn't expect it has to
 * be treated as a fatal error.
 *
 * In other words, the only real choices we have is to either pass the
 * request on to the agent as normal or kill the agent channel off.
 * This is enough to accomplish what we want, even if it means being
 * a bit rude protocol-wise.
 */
/* ARGSUSED */
static u_char *
agent_filter_requests(struct ssh *ssh, struct Channel *c,
    u_char **data, size_t *dlen)
{
	struct agent_filter_state *st;
	int r;

	debug3_f("entering");

	st = (struct agent_filter_state *)c->filter_ctx;
	if (st->direction != BUILDING_REQUEST) {
		error("Forwarded agent channel received a request "
		    "when not expecting one");
		goto dead;
	}
	r = sshbuf_putb(st->packet, c->output);
	if (r != 0) {
		error_fr(r, "sshbuf_putb");
		goto dead;
	}
	r = packet_is_complete(st->packet, AGENT_MAX_LEN);
	if (r < 0)
		goto dead;
	if (r == 1) {
		if (!accept_request_packet(st))
			goto dead;
		sshbuf_reset(st->packet);
		st->direction = BUILDING_RESPONSE;
	}

	*data = sshbuf_mutable_ptr(c->output);
	*dlen = sshbuf_len(c->output);
	return *data;

    dead:
	st->direction = AGENT_FILTER_CONNECTION_DEAD;
	return NULL;
}

static int
agent_filter_should_pass_key(struct agent_filter_state *st,
    const char *comment)
{
	if (match_pattern_list(comment,
	    options.forward_agent_filter_identities_by_comment, 0) == 1)
		return 1;
	debug("ForwardAgentFilterIdentitiesByComment won't pass key %s",
	    comment);
	return 0;
}

/*
 * Given an sshbuf where the cursor is pointing at an identity, return
 * the total size it will have. The serialized form contains a key "blob"
 * and a comment string, both of which start with a length.
 * Returns 0 on failure.
 */
static u_int32_t
peek_serialized_idsize(const struct sshbuf *pkt)
{
	const size_t total_left = sshbuf_len(pkt);
	u_int32_t size_blob, size_comment;


	if (total_left < 8)
		return 0;
	if (sshbuf_peek_u32(pkt, 0, &size_blob) != 0)
		return 0;
	if (size_blob > total_left - 8)
		return 0;
	if (sshbuf_peek_u32(pkt, 4 + size_blob, &size_comment) != 0)
		return 0;
	if (size_comment > total_left - 8 - size_blob)
		return 0;
	return 8 + size_blob + size_comment;
}

static int
agent_filter_handle_identitylist(struct agent_filter_state *st,
    struct sshbuf *out)
{
	int r;
	struct sshbuf *idbuf;
	u_int32_t ids_left;
	u_int32_t ids_kept = 0;

	debug3_f("entering");

	/*
	 * Remove the packet length and the SSH2_AGENT_IDENTITIES_ANSWER
	 * byte at the front.
	 */
	if ((r = sshbuf_consume(st->packet, 5)) != 0)
		return r; /* Shouldn't be possible! */

	/* Similar parsing logic to ssh_fetch_identitylist(): */
	if ((r = sshbuf_get_u32(st->packet, &ids_left)) != 0)
		return r;

	if (ids_left > MAX_AGENT_IDENTITIES)
		return SSH_ERR_INVALID_FORMAT;

	if ((idbuf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	debug2_f("received %u keys from agent", (unsigned int)ids_left);

	for (; ids_left > 0; ids_left--) {
		struct sshkey *key = NULL;
		char *comment = NULL;
		int keep = 0;
		const u_int32_t idsz = peek_serialized_idsize(st->packet);

		if (idsz == 0) {
			error_f("Identity received by agent channel "
			    "couldn't be parsed");
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		/*
		 * ssh_deserialize_agent_identity() will consume the data in
		 * st->packet, so add it to the output first.
		 * We'll remove it later if we decide not to pass it.
		 */
		if ((r = sshbuf_put(idbuf, sshbuf_ptr(st->packet), idsz)) != 0)
			goto out;
		if ((r = ssh_deserialize_agent_identity(st->packet,
		    &key, &comment)) == 0) {
			if (agent_filter_should_pass_key(st, comment)) {
				keep = 1;
				ids_kept++;
				identity_add_accepted(st, key);
			} else {
				sshkey_free(key);
			}
			free(comment);
		} else if (r != SSH_ERR_KEY_TYPE_UNKNOWN) {
			goto out;
		}
		if (!keep &&
		    ((r = sshbuf_consume_end(st->packet, idsz)) != 0))
			goto out;
	}
	debug2_f("kept %u keys from agent", (unsigned int)ids_left);

	if ((r = sshbuf_put_u32(out, 5 + sshbuf_len(idbuf))) != 0 ||
	    (r = sshbuf_put_u8(out, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(out, ids_kept)) != 0 ||
	    (r = sshbuf_putb(out, idbuf)) != 0)
		goto out;

    out:
	sshbuf_free(idbuf);
	return r;
}

/*
 * This handles replies from the agent to the remote side. The "input_filter"
 * side of the API is much simpler -- we just need to take the data on {buf,n}
 * and add it to c->data. Returning -1 is considered failure, anything
 * else is success.
 */
/* ARGSUSED */
static int
agent_filter_replies(struct ssh *ssh, struct Channel *c, char *buf, int len)
{
	struct agent_filter_state *st;
	int r;

	debug3_f("entering");
	st = (struct agent_filter_state *)c->filter_ctx;

	if (st->direction != BUILDING_RESPONSE) {
		error("Forwarded agent channel received a response "
		    "when not expecting one");
		goto dead;
	}
	r = sshbuf_put(st->packet, buf, len);
	if (r != 0) {
		error_fr(r, "sshbuf_put");
		goto dead;
	}
	r = packet_is_complete(st->packet, MAX_AGENT_REPLY_LEN);
	if (r < 0)
		goto dead;
	if (r == 1) {
		const u_char type = packet_type(st->packet);
		if (type == SSH2_AGENT_IDENTITIES_ANSWER) {
			r = agent_filter_handle_identitylist(st, c->input);
		} else {
			r = sshbuf_putb(c->input, st->packet);
		}
		sshbuf_reset(st->packet);
		if (r != 0) {
			error_fr(r, "Building response to agent packet "
			    "type 0x%02X", (unsigned int)type);
			goto dead;
		}
		st->direction = BUILDING_REQUEST;
	}
	return 0;

    dead:
	st->direction = AGENT_FILTER_CONNECTION_DEAD;
	return -1;
}

void
agent_filter_maybe_initialize(struct ssh *ssh, const struct Channel *c)
{
	if (options.forward_agent_filter) {
		debug("Applying filter to forwarded agent channel");
		channel_register_filter(ssh, c->self,
		    agent_filter_replies, agent_filter_requests,
		    agent_filter_cleanup, agent_filter_new());
	} else {
		debug("Forwarded agent channel will be unfiltered");
	}
}
