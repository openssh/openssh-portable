/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Adds an identity to the authentication server, or removes an identity.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 implementation,
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
RCSID("$OpenBSD: ssh-add.c,v 1.32 2001/04/08 13:03:00 markus Exp $");

#include <openssl/evp.h>

#include "ssh.h"
#include "rsa.h"
#include "log.h"
#include "xmalloc.h"
#include "key.h"
#include "authfd.h"
#include "authfile.h"
#include "pathnames.h"
#include "readpass.h"

#ifdef HAVE___PROGNAME
extern char *__progname;
#else
char *__progname;
#endif

void
delete_file(AuthenticationConnection *ac, const char *filename)
{
	Key *public;
	char *comment = NULL;

	public = key_load_public(filename, &comment);
	if (public == NULL) {
		printf("Bad key file %s\n", filename);
		return;
	}
	if (ssh_remove_identity(ac, public))
		fprintf(stderr, "Identity removed: %s (%s)\n", filename, comment);
	else
		fprintf(stderr, "Could not remove identity: %s\n", filename);
	key_free(public);
	xfree(comment);
}

/* Send a request to remove all identities. */
void
delete_all(AuthenticationConnection *ac)
{
	int success = 1;

	if (!ssh_remove_all_identities(ac, 1))
		success = 0;
	/* ignore error-code for ssh2 */
	ssh_remove_all_identities(ac, 2);

	if (success)
		fprintf(stderr, "All identities removed.\n");
	else
		fprintf(stderr, "Failed to remove all identities.\n");
}

char *
ssh_askpass(char *askpass, char *msg)
{
	pid_t pid;
	size_t len;
	char *nl, *pass;
	int p[2], status;
	char buf[1024];

	if (fflush(stdout) != 0)
		error("ssh_askpass: fflush: %s", strerror(errno));
	if (askpass == NULL)
		fatal("internal error: askpass undefined");
	if (pipe(p) < 0)
		fatal("ssh_askpass: pipe: %s", strerror(errno));
	if ((pid = fork()) < 0)
		fatal("ssh_askpass: fork: %s", strerror(errno));
	if (pid == 0) {
		close(p[0]);
		if (dup2(p[1], STDOUT_FILENO) < 0)
			fatal("ssh_askpass: dup2: %s", strerror(errno));
		execlp(askpass, askpass, msg, (char *) 0);
		fatal("ssh_askpass: exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);
	len = read(p[0], buf, sizeof buf);
	close(p[0]);
	while (waitpid(pid, &status, 0) < 0)
		if (errno != EINTR)
			break;
	if (len <= 1)
		return xstrdup("");
	nl = strchr(buf, '\n');
	if (nl)
		*nl = '\0';
	pass = xstrdup(buf);
	memset(buf, 0, sizeof(buf));
	return pass;
}

void
add_file(AuthenticationConnection *ac, const char *filename)
{
	struct stat st;
	Key *private;
	char *comment = NULL, *askpass = NULL, *pass;
	char buf[1024], msg[1024];
	int interactive = isatty(STDIN_FILENO);

	if (stat(filename, &st) < 0) {
		perror(filename);
		exit(1);
	}
	if (!interactive && getenv("DISPLAY")) {
		if (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		else
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
	}

	/* At first, try empty passphrase */
	private = key_load_private(filename, "", &comment);
	if (comment == NULL)
		comment = xstrdup(filename);
	if (private == NULL) {
		printf("Need passphrase for %.200s\n", filename);
		if (!interactive && askpass == NULL) {
			xfree(comment);
			return;
		}
		snprintf(msg, sizeof msg, "Enter passphrase for %.200s", comment);
		for (;;) {
			if (interactive) {
				snprintf(buf, sizeof buf, "%s: ", msg);
				pass = read_passphrase(buf, 1);
			} else {
				pass = ssh_askpass(askpass, msg);
			}
			if (strcmp(pass, "") == 0) {
				xfree(pass);
				xfree(comment);
				return;
			}
			private = key_load_private(filename, pass, &comment);
			memset(pass, 0, strlen(pass));
			xfree(pass);
			if (private != NULL)
				break;
			strlcpy(msg, "Bad passphrase, try again", sizeof msg);
		}
	}
	if (ssh_add_identity(ac, private, comment))
		fprintf(stderr, "Identity added: %s (%s)\n", filename, comment);
	else
		fprintf(stderr, "Could not add identity: %s\n", filename);
	xfree(comment);
	key_free(private);
}

void
list_identities(AuthenticationConnection *ac, int do_fp)
{
	Key *key;
	char *comment, *fp;
	int had_identities = 0;
	int version;

	for (version = 1; version <= 2; version++) {
		for (key = ssh_get_first_identity(ac, &comment, version);
		     key != NULL;
		     key = ssh_get_next_identity(ac, &comment, version)) {
			had_identities = 1;
			if (do_fp) {
				fp = key_fingerprint(key, SSH_FP_MD5,
				    SSH_FP_HEX);
				printf("%d %s %s (%s)\n",
				    key_size(key), fp, comment, key_type(key));
				xfree(fp);
			} else {
				if (!key_write(key, stdout))
					fprintf(stderr, "key_write failed");
				fprintf(stdout, " %s\n", comment);
			}
			key_free(key);
			xfree(comment);
		}
	}
	if (!had_identities)
		printf("The agent has no identities.\n");
}

int
main(int argc, char **argv)
{
	AuthenticationConnection *ac = NULL;
	struct passwd *pw;
	char buf[1024];
	int no_files = 1;
	int i;
	int deleting = 0;

	__progname = get_progname(argv[0]);
	init_rng();

	SSLeay_add_all_algorithms();

	/* At first, get a connection to the authentication agent. */
	ac = ssh_get_authentication_connection();
	if (ac == NULL) {
		fprintf(stderr, "Could not open a connection to your authentication agent.\n");
		exit(1);
	}
	for (i = 1; i < argc; i++) {
		if ((strcmp(argv[i], "-l") == 0) ||
		    (strcmp(argv[i], "-L") == 0)) {
			list_identities(ac, argv[i][1] == 'l' ? 1 : 0);
			/* Don't default-add/delete if -l. */
			no_files = 0;
			continue;
		}
		if (strcmp(argv[i], "-d") == 0) {
			deleting = 1;
			continue;
		}
		if (strcmp(argv[i], "-D") == 0) {
			delete_all(ac);
			no_files = 0;
			continue;
		}
		no_files = 0;
		if (deleting)
			delete_file(ac, argv[i]);
		else
			add_file(ac, argv[i]);
	}
	if (no_files) {
		pw = getpwuid(getuid());
		if (!pw) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ssh_close_authentication_connection(ac);
			exit(1);
		}
		snprintf(buf, sizeof buf, "%s/%s", pw->pw_dir, _PATH_SSH_CLIENT_IDENTITY);
		if (deleting)
			delete_file(ac, buf);
		else
			add_file(ac, buf);
	}
	ssh_close_authentication_connection(ac);
	exit(0);
}
