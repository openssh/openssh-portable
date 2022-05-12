/* $OpenBSD$ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Damien Miller.  All rights reserved.
 * Copyright (c) 2008 Jamie Beverly.
 * Copyright (c) 2022 Tobias Heider <tobias.heider@canonical.com>
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

#include "../../config.h"
#include <syslog.h>

#include <security/pam_appl.h>
#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "packet.h"
#include "hostfile.h"
#include "auth.h"
#include "authfd.h"
#include "authfile.h"
#include "auth-options.h"
#include "crypto_api.h"
#include "digest.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "servconf.h"

#define CHALLENGE_PREFIX	"pam-ssh-agent-auth-challenge"
#define CHALLENGE_NONCE_LEN	32
#define UNUSED(expr) do { (void)(expr); } while (0)

char		*authorized_keys_file = "/etc/security/authorized_keys";

void
auth_debug_add(const char *fmt,...)
{
}
void
auth_log_authopts(const char *loc, const struct sshauthopt *opts, int do_remote)
{
}

/* obtain a list of keys from the agent */
static int
pam_get_agent_identities(int *agent_fdp,
    struct ssh_identitylist **idlistp)
{
	int r, agent_fd;
	struct ssh_identitylist *idlist;

	if ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		if (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		return r;
	}
	if ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		return r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	return 0;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	FILE *f = NULL;
	struct sshbuf *sigbuf = NULL;
	u_char *nonce;
	struct sshauthopt *authoptsp = NULL;
	struct ssh_identitylist *idlist = NULL;
	int ret = PAM_AUTH_ERR, agent_fd = -1;
	struct passwd *pw = getpwuid(0);
	size_t i;

	for(; argc > 0; ++argv, argc--) {
		if(strncasecmp(*argv, "file=", strlen("file=")) == 0 ) {
			authorized_keys_file = (char *) *argv + strlen("file=");
		}
	}

	if (pam_get_agent_identities(&agent_fd, &idlist) != 0) {
		pam_syslog(pamh, LOG_CRIT, "pam_get_agent_identities() failed.");
		goto exit;
	}

	if ((f = auth_openkeyfile(authorized_keys_file, pw, 1)) == NULL) {
		pam_syslog(pamh, LOG_CRIT, "authorized_keys open failed.");
		goto exit;
	}

	for (i = 0; i < idlist->nkeys; i++) {
		/* Check if key in authorized_keys */
		if (!auth_check_authkeys_file(pw, f, authorized_keys_file,
		    idlist->keys[i], NULL, NULL, &authoptsp))
			continue;

		/* Generate random challenge */
		if ((sigbuf = sshbuf_new()) == NULL ||
		    sshbuf_put_cstring(sigbuf, CHALLENGE_PREFIX) != 0 ||
		    sshbuf_reserve(sigbuf, CHALLENGE_NONCE_LEN, &nonce) != 0)
			goto exit;

		arc4random_buf(nonce, CHALLENGE_NONCE_LEN);

		/* Sign challenge via ssh-agent */
		u_char *sig = NULL;
		size_t	slen = 0;
		if (ssh_agent_sign(agent_fd, idlist->keys[i], &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), NULL, 0) != 0)
			goto exit;

		/* Verify signature */
		if (sshkey_verify(idlist->keys[i], sig, slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf),
		    NULL, 0, NULL) == 0) {
			pam_syslog(pamh, LOG_INFO, "Found matching %s key: %s",
			    sshkey_type(idlist->keys[i]),
			    sshkey_fingerprint(idlist->keys[i], SSH_DIGEST_SHA256,
			    SSH_FP_DEFAULT));

			ret = PAM_SUCCESS;
			break;
		}
		sshbuf_free(sigbuf);
		sigbuf = NULL;
	}

 exit:
	if (f != NULL)
		fclose(f);
	ssh_free_identitylist(idlist);
	sshbuf_free(sigbuf);

	return ret;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	UNUSED(pamh);
	UNUSED(flags);
	UNUSED(argc);
	UNUSED(argv);
	return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_ssh_agent_auth_modstruct = {
	"pam_ssh_agent_auth",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	NULL,
	NULL,
	NULL,
};
#endif
