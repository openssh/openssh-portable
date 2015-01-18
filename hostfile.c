/* $OpenBSD: hostfile.c,v 1.60 2015/01/18 21:40:23 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for manipulating the known hosts files.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * Copyright (c) 1999, 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 1999 Niels Provos.  All rights reserved.
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

#include "includes.h"

#include <sys/types.h>

#include <netinet/in.h>

#include <errno.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "match.h"
#include "sshkey.h"
#include "hostfile.h"
#include "log.h"
#include "misc.h"
#include "ssherr.h"
#include "digest.h"
#include "hmac.h"

struct hostkeys {
	struct hostkey_entry *entries;
	u_int num_entries;
};

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

static int
extract_salt(const char *s, u_int l, u_char *salt, size_t salt_len)
{
	char *p, *b64salt;
	u_int b64len;
	int ret;

	if (l < sizeof(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		return (-1);
	}
	if (strncmp(s, HASH_MAGIC, sizeof(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		return (-1);
	}
	s += sizeof(HASH_MAGIC) - 1;
	l -= sizeof(HASH_MAGIC) - 1;
	if ((p = memchr(s, HASH_DELIM, l)) == NULL) {
		debug2("extract_salt: missing salt termination character");
		return (-1);
	}

	b64len = p - s;
	/* Sanity check */
	if (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		return (-1);
	}
	b64salt = xmalloc(1 + b64len);
	memcpy(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	free(b64salt);
	if (ret == -1) {
		debug2("extract_salt: salt decode error");
		return (-1);
	}
	if (ret != (int)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		return (-1);
	}

	return (0);
}

char *
host_hash(const char *host, const char *name_from_hostfile, u_int src_len)
{
	struct ssh_hmac_ctx *ctx;
	u_char salt[256], result[256];
	char uu_salt[512], uu_result[512];
	static char encoded[1024];
	u_int i, len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	if (name_from_hostfile == NULL) {
		/* Create new salt */
		for (i = 0; i < len; i++)
			salt[i] = arc4random();
	} else {
		/* Extract salt from known host entry */
		if (extract_salt(name_from_hostfile, src_len, salt,
		    sizeof(salt)) == -1)
			return (NULL);
	}

	if ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == NULL ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, strlen(host)) < 0 ||
	    ssh_hmac_final(ctx, result, sizeof(result)))
		fatal("%s: ssh_hmac failed", __func__);
	ssh_hmac_free(ctx);

	if (__b64_ntop(salt, len, uu_salt, sizeof(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, sizeof(uu_result)) == -1)
		fatal("%s: __b64_ntop failed", __func__);

	snprintf(encoded, sizeof(encoded), "%s%s%c%s", HASH_MAGIC, uu_salt,
	    HASH_DELIM, uu_result);

	return (encoded);
}

/*
 * Parses an RSA (number of bits, e, n) or DSA key from a string.  Moves the
 * pointer over the key.  Skips any whitespace at the beginning and at end.
 */

int
hostfile_read_key(char **cpp, u_int *bitsp, struct sshkey *ret)
{
	char *cp;
	int r;

	/* Skip leading whitespace. */
	for (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	if ((r = sshkey_read(ret, &cp)) != 0)
		return 0;

	/* Skip trailing whitespace. */
	for (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	if (bitsp != NULL)
		*bitsp = sshkey_size(ret);
	return 1;
}

static int
hostfile_check_key(int bits, const struct sshkey *key, const char *host,
    const char *filename, u_long linenum)
{
#ifdef WITH_SSH1
	if (key == NULL || key->type != KEY_RSA1 || key->rsa == NULL)
		return 1;
	if (bits != BN_num_bits(key->rsa->n)) {
		logit("Warning: %s, line %lu: keysize mismatch for host %s: "
		    "actual %d vs. announced %d.",
		    filename, linenum, host, BN_num_bits(key->rsa->n), bits);
		logit("Warning: replace %d with %d in %s, line %lu.",
		    bits, BN_num_bits(key->rsa->n), filename, linenum);
	}
#endif
	return 1;
}

static HostkeyMarker
check_markers(char **cpp)
{
	char marker[32], *sp, *cp = *cpp;
	int ret = MRK_NONE;

	while (*cp == '@') {
		/* Only one marker is allowed */
		if (ret != MRK_NONE)
			return MRK_ERROR;
		/* Markers are terminated by whitespace */
		if ((sp = strchr(cp, ' ')) == NULL &&
		    (sp = strchr(cp, '\t')) == NULL)
			return MRK_ERROR;
		/* Extract marker for comparison */
		if (sp <= cp + 1 || sp >= cp + sizeof(marker))
			return MRK_ERROR;
		memcpy(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		if (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		else if (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		else
			return MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		for (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	return ret;
}

struct hostkeys *
init_hostkeys(void)
{
	struct hostkeys *ret = xcalloc(1, sizeof(*ret));

	ret->entries = NULL;
	return ret;
}

void
load_hostkeys(struct hostkeys *hostkeys, const char *host, const char *path)
{
	FILE *f;
	char line[8192];
	u_long linenum = 0, num_loaded = 0;
	char *cp, *cp2, *hashed_host;
	HostkeyMarker marker;
	struct sshkey *key;
	u_int kbits;

	if ((f = fopen(path, "r")) == NULL)
		return;
	debug3("%s: loading entries for host \"%.100s\" from file \"%s\"",
	    __func__, host, path);
	while (read_keyfile_line(f, path, line, sizeof(line), &linenum) == 0) {
		cp = line;

		/* Skip any leading whitespace, comments and empty lines. */
		for (; *cp == ' ' || *cp == '\t'; cp++)
			;
		if (!*cp || *cp == '#' || *cp == '\n')
			continue;

		if ((marker = check_markers(&cp)) == MRK_ERROR) {
			verbose("%s: invalid marker at %s:%lu",
			    __func__, path, linenum);
			continue;
		}

		/* Find the end of the host name portion. */
		for (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;

		/* Check if the host name matches. */
		if (match_hostname(host, cp, (u_int) (cp2 - cp)) != 1) {
			if (*cp != HASH_DELIM)
				continue;
			hashed_host = host_hash(host, cp, (u_int) (cp2 - cp));
			if (hashed_host == NULL) {
				debug("Invalid hashed host line %lu of %s",
				    linenum, path);
				continue;
			}
			if (strncmp(hashed_host, cp, (u_int) (cp2 - cp)) != 0)
				continue;
		}

		/* Got a match.  Skip host name. */
		cp = cp2;

		/*
		 * Extract the key from the line.  This will skip any leading
		 * whitespace.  Ignore badly formatted lines.
		 */
		if ((key = sshkey_new(KEY_UNSPEC)) == NULL) {
			error("%s: sshkey_new failed", __func__);
			break;
		}
		if (!hostfile_read_key(&cp, &kbits, key)) {
			sshkey_free(key);
#ifdef WITH_SSH1
			if ((key = sshkey_new(KEY_RSA1)) == NULL) {
				error("%s: sshkey_new failed", __func__);
				break;
			}
			if (!hostfile_read_key(&cp, &kbits, key)) {
				sshkey_free(key);
				continue;
			}
#else
			continue;
#endif
		}
		if (!hostfile_check_key(kbits, key, host, path, linenum))
			continue;

		debug3("%s: found %skey type %s in file %s:%lu", __func__,
		    marker == MRK_NONE ? "" :
		    (marker == MRK_CA ? "ca " : "revoked "),
		    sshkey_type(key), path, linenum);
		hostkeys->entries = xrealloc(hostkeys->entries,
		    hostkeys->num_entries + 1, sizeof(*hostkeys->entries));
		hostkeys->entries[hostkeys->num_entries].host = xstrdup(host);
		hostkeys->entries[hostkeys->num_entries].file = xstrdup(path);
		hostkeys->entries[hostkeys->num_entries].line = linenum;
		hostkeys->entries[hostkeys->num_entries].key = key;
		hostkeys->entries[hostkeys->num_entries].marker = marker;
		hostkeys->num_entries++;
		num_loaded++;
	}
	debug3("%s: loaded %lu keys", __func__, num_loaded);
	fclose(f);
	return;
}

void
free_hostkeys(struct hostkeys *hostkeys)
{
	u_int i;

	for (i = 0; i < hostkeys->num_entries; i++) {
		free(hostkeys->entries[i].host);
		free(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].key);
		explicit_bzero(hostkeys->entries + i, sizeof(*hostkeys->entries));
	}
	free(hostkeys->entries);
	explicit_bzero(hostkeys, sizeof(*hostkeys));
	free(hostkeys);
}

static int
check_key_not_revoked(struct hostkeys *hostkeys, struct sshkey *k)
{
	int is_cert = sshkey_is_cert(k);
	u_int i;

	for (i = 0; i < hostkeys->num_entries; i++) {
		if (hostkeys->entries[i].marker != MRK_REVOKE)
			continue;
		if (sshkey_equal_public(k, hostkeys->entries[i].key))
			return -1;
		if (is_cert &&
		    sshkey_equal_public(k->cert->signature_key,
		    hostkeys->entries[i].key))
			return -1;
	}
	return 0;
}

/*
 * Match keys against a specified key, or look one up by key type.
 *
 * If looking for a keytype (key == NULL) and one is found then return
 * HOST_FOUND, otherwise HOST_NEW.
 *
 * If looking for a key (key != NULL):
 *  1. If the key is a cert and a matching CA is found, return HOST_OK
 *  2. If the key is not a cert and a matching key is found, return HOST_OK
 *  3. If no key matches but a key with a different type is found, then
 *     return HOST_CHANGED
 *  4. If no matching keys are found, then return HOST_NEW.
 *
 * Finally, check any found key is not revoked.
 */
static HostStatus
check_hostkeys_by_key_or_type(struct hostkeys *hostkeys,
    struct sshkey *k, int keytype, const struct hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	int want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;
	int proto = (k ? k->type : keytype) == KEY_RSA1 ? 1 : 2;

	if (found != NULL)
		*found = NULL;

	for (i = 0; i < hostkeys->num_entries; i++) {
		if (proto == 1 && hostkeys->entries[i].key->type != KEY_RSA1)
			continue;
		if (proto == 2 && hostkeys->entries[i].key->type == KEY_RSA1)
			continue;
		if (hostkeys->entries[i].marker != want_marker)
			continue;
		if (k == NULL) {
			if (hostkeys->entries[i].key->type != keytype)
				continue;
			end_return = HOST_FOUND;
			if (found != NULL)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].key;
			break;
		}
		if (want_cert) {
			if (sshkey_equal_public(k->cert->signature_key,
			    hostkeys->entries[i].key)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				if (found != NULL)
					*found = hostkeys->entries + i;
				break;
			}
		} else {
			if (sshkey_equal(k, hostkeys->entries[i].key)) {
				end_return = HOST_OK;
				if (found != NULL)
					*found = hostkeys->entries + i;
				break;
			}
			/* A non-maching key exists */
			end_return = HOST_CHANGED;
			if (found != NULL)
				*found = hostkeys->entries + i;
		}
	}
	if (check_key_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		if (found != NULL)
			*found = NULL;
	}
	return end_return;
}

HostStatus
check_key_in_hostkeys(struct hostkeys *hostkeys, struct sshkey *key,
    const struct hostkey_entry **found)
{
	if (key == NULL)
		fatal("no key to look up");
	return check_hostkeys_by_key_or_type(hostkeys, key, 0, found);
}

int
lookup_key_in_hostkeys_by_type(struct hostkeys *hostkeys, int keytype,
    const struct hostkey_entry **found)
{
	return (check_hostkeys_by_key_or_type(hostkeys, NULL, keytype,
	    found) == HOST_FOUND);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */

int
add_host_to_hostfile(const char *filename, const char *host,
    const struct sshkey *key, int store_hash)
{
	FILE *f;
	int r, success = 0;
	char *hashed_host = NULL;

	if (key == NULL)
		return 1;	/* XXX ? */
	f = fopen(filename, "a");
	if (!f)
		return 0;

	if (store_hash) {
		if ((hashed_host = host_hash(host, NULL, 0)) == NULL) {
			error("add_host_to_hostfile: host_hash failed");
			fclose(f);
			return 0;
		}
	}
	fprintf(f, "%s ", store_hash ? hashed_host : host);

	if ((r = sshkey_write(key, f)) != 0) {
		error("%s: saving key in %s failed: %s",
		    __func__, filename, ssh_err(r));
	} else
		success = 1;
	fputc('\n', f);
	fclose(f);
	return success;
}

static int
match_maybe_hashed(const char *host, const char *names, int *was_hashed)
{
	int hashed = *names == HASH_DELIM;
	const char *hashed_host;
	size_t nlen = strlen(names);

	if (was_hashed != NULL)
		*was_hashed = hashed;
	if (hashed) {
		if ((hashed_host = host_hash(host, names, nlen)) == NULL)
			return -1;
		return nlen == strlen(hashed_host) &&
		    strncmp(hashed_host, names, nlen) == 0;
	}
	return match_hostname(host, names, nlen) == 1;
}

int
hostkeys_foreach(const char *path, hostkeys_foreach_fn *callback, void *ctx,
    const char *host, u_int options)
{
	FILE *f;
	char line[8192], oline[8192];
	u_long linenum = 0;
	char *cp, *cp2;
	u_int kbits;
	int s, r = 0;
	struct hostkey_foreach_line lineinfo;

	memset(&lineinfo, 0, sizeof(lineinfo));
	if (host == NULL && (options & HKF_WANT_MATCH_HOST) != 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((f = fopen(path, "r")) == NULL)
		return SSH_ERR_SYSTEM_ERROR;

	debug3("%s: reading file \"%s\"", __func__, path);
	while (read_keyfile_line(f, path, line, sizeof(line), &linenum) == 0) {
		line[strcspn(line, "\n")] = '\0';
		strlcpy(oline, line, sizeof(oline));

		sshkey_free(lineinfo.key);
		memset(&lineinfo, 0, sizeof(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.line = oline;
		lineinfo.status = HKF_STATUS_OK;

		/* Skip any leading whitespace, comments and empty lines. */
		for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		if (!*cp || *cp == '#' || *cp == '\n') {
			if ((options & HKF_WANT_MATCH_HOST) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				if ((r = callback(&lineinfo, ctx)) != 0)
					break;
			}
			continue;
		}

		if ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose("%s: invalid marker at %s:%lu",
			    __func__, path, linenum);
			if ((options & HKF_WANT_MATCH_HOST) == 0)
				goto bad;
			continue;
		}

		/* Find the end of the host name portion. */
		for (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		if (host != NULL) {
			s = match_maybe_hashed(host, lineinfo.hosts,
			    &lineinfo.was_hashed);
			if (s == 1)
				lineinfo.status = HKF_STATUS_HOST_MATCHED;
			else if ((options & HKF_WANT_MATCH_HOST) != 0)
				continue;
			else if (s == -1) {
				debug2("%s: %s:%ld: bad host hash \"%.32s\"",
				    __func__, path, linenum, lineinfo.hosts);
				goto bad;
			}
		}

		/* Got a match.  Skip host name and any following whitespace */
		for (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		if (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key", path, linenum);
			goto bad;
		}
		lineinfo.rawkey = cp = cp2;

		if ((options & HKF_WANT_PARSE_KEY) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			if ((lineinfo.key = sshkey_new(KEY_UNSPEC)) == NULL) {
				error("%s: sshkey_new failed", __func__);
				return SSH_ERR_ALLOC_FAIL;
			}
			if (!hostfile_read_key(&cp, &kbits, lineinfo.key)) {
#ifdef WITH_SSH1
				sshkey_free(lineinfo.key);
				lineinfo.key = sshkey_new(KEY_RSA1);
				if (lineinfo.key  == NULL) {
					error("%s: sshkey_new fail", __func__);
					return SSH_ERR_ALLOC_FAIL;
				}
				if (!hostfile_read_key(&cp, &kbits,
				    lineinfo.key))
					goto bad;
#else
				goto bad;
#endif
			}
			if (!hostfile_check_key(kbits, lineinfo.key, host,
			    path, linenum)) {
 bad:
				lineinfo.status = HKF_STATUS_INVALID;
				if ((r = callback(&lineinfo, ctx)) != 0)
					break;
				continue;
			}
		}
		if ((r = callback(&lineinfo, ctx)) != 0)
			break;
	}
	sshkey_free(lineinfo.key);
	fclose(f);
	return r;
}
