/*
 *
 * authfd.c
 *
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 *
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * Created: Wed Mar 29 01:30:28 1995 ylo
 *
 * Functions for connecting the local authentication agent.
 *
 */

#include "includes.h"
RCSID("$OpenBSD: authfd.c,v 1.24 2000/08/15 19:20:46 markus Exp $");

#include "ssh.h"
#include "rsa.h"
#include "buffer.h"
#include "bufaux.h"
#include "xmalloc.h"
#include "getput.h"

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include "key.h"
#include "authfd.h"
#include "kex.h"

/* helper */
int	decode_reply(int type);

/* Returns the number of the authentication fd, or -1 if there is none. */

int
ssh_get_authentication_socket()
{
	const char *authsocket;
	int sock, len;
	struct sockaddr_un sunaddr;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	if (!authsocket)
		return -1;

	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, sizeof(sunaddr.sun_path));
#ifdef HAVE_SUN_LEN_IN_SOCKADDR_UN
	sunaddr.sun_len = len = SUN_LEN(&sunaddr)+1;
#else /* HAVE_SUN_LEN_IN_SOCKADDR_UN */
	len = SUN_LEN(&sunaddr)+1;
#endif /* HAVE_SUN_LEN_IN_SOCKADDR_UN */

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	/* close on exec */
	if (fcntl(sock, F_SETFD, 1) == -1) {
		close(sock);
		return -1;
	}
	if (connect(sock, (struct sockaddr *) & sunaddr, len) < 0) {
		close(sock);
		return -1;
	}
	return sock;
}

int
ssh_request_reply(AuthenticationConnection *auth,
    Buffer *request, Buffer *reply)
{
	int l, len;
	char buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = buffer_len(request);
	PUT_32BIT(buf, len);

	/* Send the length and then the packet to the agent. */
	if (atomicio(write, auth->fd, buf, 4) != 4 ||
	    atomicio(write, auth->fd, buffer_ptr(request),
	    buffer_len(request)) != buffer_len(request)) {
		error("Error writing to authentication socket.");
		return 0;
	}
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	len = 4;
	while (len > 0) {
		l = read(auth->fd, buf + 4 - len, len);
		if (l <= 0) {
			error("Error reading response length from authentication socket.");
			return 0;
		}
		len -= l;
	}

	/* Extract the length, and check it for sanity. */
	len = GET_32BIT(buf);
	if (len > 256 * 1024)
		fatal("Authentication response too long: %d", len);

	/* Read the rest of the response in to the buffer. */
	buffer_clear(reply);
	while (len > 0) {
		l = len;
		if (l > sizeof(buf))
			l = sizeof(buf);
		l = read(auth->fd, buf, l);
		if (l <= 0) {
			error("Error reading response from authentication socket.");
			return 0;
		}
		buffer_append(reply, (char *) buf, l);
		len -= l;
	}
	return 1;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */

void
ssh_close_authentication_socket(int sock)
{
	if (getenv(SSH_AUTHSOCKET_ENV_NAME))
		close(sock);
}

/*
 * Opens and connects a private socket for communication with the
 * authentication agent.  Returns the file descriptor (which must be
 * shut down and closed by the caller when no longer needed).
 * Returns NULL if an error occurred and the connection could not be
 * opened.
 */

AuthenticationConnection *
ssh_get_authentication_connection()
{
	AuthenticationConnection *auth;
	int sock;

	sock = ssh_get_authentication_socket();

	/*
	 * Fail if we couldn't obtain a connection.  This happens if we
	 * exited due to a timeout.
	 */
	if (sock < 0)
		return NULL;

	auth = xmalloc(sizeof(*auth));
	auth->fd = sock;
	buffer_init(&auth->packet);
	buffer_init(&auth->identities);
	auth->howmany = 0;

	return auth;
}

/*
 * Closes the connection to the authentication agent and frees any associated
 * memory.
 */

void
ssh_close_authentication_connection(AuthenticationConnection *ac)
{
	buffer_free(&ac->packet);
	buffer_free(&ac->identities);
	close(ac->fd);
	xfree(ac);
}

/*
 * Returns the first authentication identity held by the agent.
 * Returns true if an identity is available, 0 otherwise.
 * The caller must initialize the integers before the call, and free the
 * comment after a successful call (before calling ssh_get_next_identity).
 */

int
ssh_get_first_identity(AuthenticationConnection *auth,
    BIGNUM *e, BIGNUM *n, char **comment)
{
	Buffer request;
	int type;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	buffer_init(&request);
	buffer_put_char(&request, SSH_AGENTC_REQUEST_RSA_IDENTITIES);

	buffer_clear(&auth->identities);
	if (ssh_request_reply(auth, &request, &auth->identities) == 0) {
		buffer_free(&request);
		return 0;
	}
	buffer_free(&request);

	/* Get message type, and verify that we got a proper answer. */
	type = buffer_get_char(&auth->identities);
	if (type != SSH_AGENT_RSA_IDENTITIES_ANSWER)
		fatal("Bad authentication reply message type: %d", type);

	/* Get the number of entries in the response and check it for sanity. */
	auth->howmany = buffer_get_int(&auth->identities);
	if (auth->howmany > 1024)
		fatal("Too many identities in authentication reply: %d\n",
		    auth->howmany);

	/* Return the first entry (if any). */
	return ssh_get_next_identity(auth, e, n, comment);
}

/*
 * Returns the next authentication identity for the agent.  Other functions
 * can be called between this and ssh_get_first_identity or two calls of this
 * function.  This returns 0 if there are no more identities.  The caller
 * must free comment after a successful return.
 */

int
ssh_get_next_identity(AuthenticationConnection *auth,
    BIGNUM *e, BIGNUM *n, char **comment)
{
	unsigned int bits;

	/* Return failure if no more entries. */
	if (auth->howmany <= 0)
		return 0;

	/*
	 * Get the next entry from the packet.  These will abort with a fatal
	 * error if the packet is too short or contains corrupt data.
	 */
	bits = buffer_get_int(&auth->identities);
	buffer_get_bignum(&auth->identities, e);
	buffer_get_bignum(&auth->identities, n);
	*comment = buffer_get_string(&auth->identities, NULL);

	if (bits != BN_num_bits(n))
		log("Warning: identity keysize mismatch: actual %d, announced %u",
		    BN_num_bits(n), bits);

	/* Decrement the number of remaining entries. */
	auth->howmany--;

	return 1;
}

/*
 * Generates a random challenge, sends it to the agent, and waits for
 * response from the agent.  Returns true (non-zero) if the agent gave the
 * correct answer, zero otherwise.  Response type selects the style of
 * response desired, with 0 corresponding to protocol version 1.0 (no longer
 * supported) and 1 corresponding to protocol version 1.1.
 */

int
ssh_decrypt_challenge(AuthenticationConnection *auth,
    BIGNUM* e, BIGNUM *n, BIGNUM *challenge,
    unsigned char session_id[16],
    unsigned int response_type,
    unsigned char response[16])
{
	Buffer buffer;
	int success = 0;
	int i;
	int type;

	if (response_type == 0)
		fatal("Compatibility with ssh protocol version "
		    "1.0 no longer supported.");

	buffer_init(&buffer);
	buffer_put_char(&buffer, SSH_AGENTC_RSA_CHALLENGE);
	buffer_put_int(&buffer, BN_num_bits(n));
	buffer_put_bignum(&buffer, e);
	buffer_put_bignum(&buffer, n);
	buffer_put_bignum(&buffer, challenge);
	buffer_append(&buffer, (char *) session_id, 16);
	buffer_put_int(&buffer, response_type);

	if (ssh_request_reply(auth, &buffer, &buffer) == 0) {
		buffer_free(&buffer);
		return 0;
	}
	type = buffer_get_char(&buffer);

	if (type == SSH_AGENT_FAILURE) {
		log("Agent admitted failure to authenticate using the key.");
	} else if (type != SSH_AGENT_RSA_RESPONSE) {
		fatal("Bad authentication response: %d", type);
	} else {
		success = 1;
		/*
		 * Get the response from the packet.  This will abort with a
		 * fatal error if the packet is corrupt.
		 */
		for (i = 0; i < 16; i++)
			response[i] = buffer_get_char(&buffer);
	}
	buffer_free(&buffer);
	return success;
}

/* Encode key for a message to the agent. */

void
ssh_encode_identity_rsa(Buffer *b, RSA *key, const char *comment)
{
	buffer_clear(b);
	buffer_put_char(b, SSH_AGENTC_ADD_RSA_IDENTITY);
	buffer_put_int(b, BN_num_bits(key->n));
	buffer_put_bignum(b, key->n);
	buffer_put_bignum(b, key->e);
	buffer_put_bignum(b, key->d);
	/* To keep within the protocol: p < q for ssh. in SSL p > q */
	buffer_put_bignum(b, key->iqmp);	/* ssh key->u */
	buffer_put_bignum(b, key->q);	/* ssh key->p, SSL key->q */
	buffer_put_bignum(b, key->p);	/* ssh key->q, SSL key->p */
	buffer_put_string(b, comment, strlen(comment));
}

void
ssh_encode_identity_dsa(Buffer *b, DSA *key, const char *comment)
{
	buffer_clear(b);
	buffer_put_char(b, SSH2_AGENTC_ADD_IDENTITY);
	buffer_put_cstring(b, KEX_DSS);
	buffer_put_bignum2(b, key->p);
	buffer_put_bignum2(b, key->q);
	buffer_put_bignum2(b, key->g);
	buffer_put_bignum2(b, key->pub_key);
	buffer_put_bignum2(b, key->priv_key);
	buffer_put_string(b, comment, strlen(comment));
}

/*
 * Adds an identity to the authentication server.  This call is not meant to
 * be used by normal applications.
 */

int
ssh_add_identity(AuthenticationConnection *auth, Key *key, const char *comment)
{
	Buffer buffer;
	int type;

	buffer_init(&buffer);

	switch (key->type) {
	case KEY_RSA:
		ssh_encode_identity_rsa(&buffer, key->rsa, comment);
		break;
	case KEY_DSA:
		ssh_encode_identity_dsa(&buffer, key->dsa, comment);
		break;
	default:
		buffer_free(&buffer);
		return 0;
		break;
	}
	if (ssh_request_reply(auth, &buffer, &buffer) == 0) {
		buffer_free(&buffer);
		return 0;
	}
	type = buffer_get_char(&buffer);
	buffer_free(&buffer);
	return decode_reply(type);
}

/*
 * Removes an identity from the authentication server.  This call is not
 * meant to be used by normal applications.
 */

int
ssh_remove_identity(AuthenticationConnection *auth, RSA *key)
{
	Buffer buffer;
	int type;

	buffer_init(&buffer);
	buffer_put_char(&buffer, SSH_AGENTC_REMOVE_RSA_IDENTITY);
	buffer_put_int(&buffer, BN_num_bits(key->n));
	buffer_put_bignum(&buffer, key->e);
	buffer_put_bignum(&buffer, key->n);

	if (ssh_request_reply(auth, &buffer, &buffer) == 0) {
		buffer_free(&buffer);
		return 0;
	}
	type = buffer_get_char(&buffer);
	buffer_free(&buffer);
	return decode_reply(type);
}

/*
 * Removes all identities from the agent.  This call is not meant to be used
 * by normal applications.
 */

int
ssh_remove_all_identities(AuthenticationConnection *auth)
{
	Buffer buffer;
	int type;

	buffer_init(&buffer);
	buffer_put_char(&buffer, SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES);

	if (ssh_request_reply(auth, &buffer, &buffer) == 0) {
		buffer_free(&buffer);
		return 0;
	}
	type = buffer_get_char(&buffer);
	buffer_free(&buffer);
	return decode_reply(type);
}

int 
decode_reply(int type)
{
	switch (type) {
	case SSH_AGENT_FAILURE:
		log("SSH_AGENT_FAILURE");
		return 0;
	case SSH_AGENT_SUCCESS:
		return 1;
	default:
		fatal("Bad response from authentication agent: %d", type);
	}
	/* NOTREACHED */
	return 0;
}
