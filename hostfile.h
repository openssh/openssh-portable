/* $OpenBSD: hostfile.h,v 1.21 2015/01/15 09:40:00 djm Exp $ */

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

#endif
