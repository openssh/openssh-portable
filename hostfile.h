/* $OpenBSD: hostfile.h,v 1.22 2015/01/18 21:40:24 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
#ifndef HOSTFILE_H
#define HOSTFILE_H

typedef enum {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

typedef enum {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

struct hostkey_entry {
	char *host;
	char *file;
	u_long line;
	struct sshkey *key;
	HostkeyMarker marker;
};
struct hostkeys;

struct hostkeys *init_hostkeys(void);
void	 load_hostkeys(struct hostkeys *, const char *, const char *);
void	 free_hostkeys(struct hostkeys *);

HostStatus check_key_in_hostkeys(struct hostkeys *, struct sshkey *,
    const struct hostkey_entry **);
int	 lookup_key_in_hostkeys_by_type(struct hostkeys *, int,
    const struct hostkey_entry **);

int	 hostfile_read_key(char **, u_int *, struct sshkey *);
int	 add_host_to_hostfile(const char *, const char *,
    const struct sshkey *, int);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

char	*host_hash(const char *, const char *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#define HKF_WANT_MATCH_HOST	(1)	/* return only matching hosts */
#define HKF_WANT_PARSE_KEY	(1<<1)	/* need key parsed */

#define HKF_STATUS_OK		1	/* Line parsed, didn't match host */
#define HKF_STATUS_INVALID	2	/* line had parse error */
#define HKF_STATUS_COMMENT	3	/* valid line contained no key */
#define HKF_STATUS_HOST_MATCHED	4	/* hostname matched */

/*
 * The callback function receives this as an argument for each matching 
 * hostkey line. The callback may "steal" the 'key' field by setting it to NULL.
 * If a parse error occurred, then "hosts" and subsequent options may be NULL.
 */
struct hostkey_foreach_line {
	const char *path; /* Path of file */
	u_long linenum;	/* Line number */
	int status;	/* One of HKF_STATUS_* */
	char *line;	/* Entire key line; mutable by callback */
	int marker;	/* CA/revocation markers; indicated by MRK_* value */
	const char *hosts; /* Raw hosts text, may be hashed or list multiple */
	int was_hashed;	/* Non-zero if hostname was hashed */
	const char *rawkey; /* Text of key and any comment following it */
	struct sshkey *key; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	const char *comment; /* Any comment following the key */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
typedef int hostkeys_foreach_fn(struct hostkey_foreach_line *l, void *ctx);

int hostkeys_foreach(const char *path, hostkeys_foreach_fn *callback, void *ctx,
    const char *host, u_int options);

#endif
