/* $OpenBSD: sftp-client.h,v 1.8 2002/02/12 12:32:27 djm Exp $ */

/*
 * Copyright (c) 2001-2002 Damien Miller.  All rights reserved.
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

/* Client side of SSH2 filexfer protocol */

typedef struct SFTP_DIRENT SFTP_DIRENT;

struct SFTP_DIRENT {
	char *filename;
	char *longname;
	Attrib a;
};

/*
 * Initialiase a SSH filexfer connection. Returns -1 on error or
 * protocol version on success.
 */
int do_init(int, int);

/* Close file referred to by 'handle' */
int do_close(int, int, char *, u_int);

/* List contents of directory 'path' to stdout */
int do_ls(int, int, char *);

/* Read contents of 'path' to NULL-terminated array 'dir' */
int do_readdir(int, int, char *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from do_readdir) */
void free_sftp_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
int do_rm(int, int, char *);

/* Create directory 'path' */
int do_mkdir(int, int, char *, Attrib *);

/* Remove directory 'path' */
int do_rmdir(int, int, char *);

/* Get file attributes of 'path' (follows symlinks) */
Attrib *do_stat(int, int, char *, int);

/* Get file attributes of 'path' (does not follow symlinks) */
Attrib *do_lstat(int, int, char *, int);

/* Get file attributes of open file 'handle' */
Attrib *do_fstat(int, int, char *, u_int, int);

/* Set file attributes of 'path' */
int do_setstat(int, int, char *, Attrib *);

/* Set file attributes of open file 'handle' */
int do_fsetstat(int, int, char *, u_int, Attrib *);

/* Canonicalise 'path' - caller must free result */
char *do_realpath(int, int, char *);

/* Rename 'oldpath' to 'newpath' */
int do_rename(int, int, char *, char *);

/* Rename 'oldpath' to 'newpath' */
int do_symlink(int, int, char *, char *);

/* Return target of symlink 'path' - caller must free result */
char *do_readlink(int, int, char *);

/* XXX: add callbacks to do_download/do_upload so we can do progress meter */

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
int do_download(int, int, char *, char *, int, size_t, int);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
int do_upload(int, int, char *, char *, int , size_t, int);
