#include "includes.h"

#ifdef HAVE_OSF_SIA
#include "ssh.h"
#include "auth-sia.h"
#include "log.h"
#include "servconf.h"
#include "canohost.h"
#include "auth.h"

#include <sia.h>
#include <siad.h>
#include <pwd.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>

extern ServerOptions options;
extern int saved_argc;
extern char **saved_argv;

extern int errno;

int
auth_sia_password(Authctxt *authctxt, char *pass)
{
	int ret;
	SIAENTITY *ent = NULL;
	const char *host;
	char *user = authctxt->user;

	host = get_canonical_hostname(options.verify_reverse_mapping);

	if (!user || !pass || pass[0] == '\0')
		return(0);

	if (sia_ses_init(&ent, saved_argc, saved_argv, host, user, NULL, 0,
	    NULL) != SIASUCCESS)
		return(0);

	if ((ret = sia_ses_authent(NULL, pass, ent)) != SIASUCCESS) {
		error("couldn't authenticate %s from %s", user, host);
		if (ret & SIASTOP)
			sia_ses_release(&ent);
		return(0);
	}

	sia_ses_release(&ent);

	return(1);
}

void
session_setup_sia(char *user, char *tty)
{
	int ret;
	struct passwd *pw;
	SIAENTITY *ent = NULL;
	const char *host;

	host = get_canonical_hostname (options.verify_reverse_mapping);

	if (sia_ses_init(&ent, saved_argc, saved_argv, host, user, tty, 0,
	    NULL) != SIASUCCESS) {
		error("sia_ses_init failed");
		exit(1);
	}

	if ((pw = getpwnam(user)) == NULL) {
		sia_ses_release(&ent);
		error("getpwnam(%s) failed: %s", user, strerror(errno));
		exit(1);
	}
	if (sia_make_entity_pwd(pw, ent) != SIASUCCESS) {
		sia_ses_release(&ent);
		error("sia_make_entity_pwd failed");
		exit(1);
	}

	ent->authtype = SIA_A_NONE;
	if (sia_ses_estab(sia_collect_trm, ent) != SIASUCCESS) {
		error("couldn't establish session for %s from %s", user,
		    host);
		exit(1);
	}

	if (setpriority(PRIO_PROCESS, 0, 0) == -1) {
		sia_ses_release(&ent);
		error("setpriority failed: %s", strerror (errno));
		exit(1);
	}

	if (sia_ses_launch(sia_collect_trm, ent) != SIASUCCESS) {
		error("couldn't launch session for %s from %s", user, host);
		exit(1);
	}
	
	sia_ses_release(&ent);

	if (setreuid(geteuid(), geteuid()) < 0) {
		error("setreuid failed: %s", strerror (errno));
		exit(1);
	}
}

#endif /* HAVE_OSF_SIA */

