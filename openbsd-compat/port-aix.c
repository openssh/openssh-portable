#include "includes.h"

#ifdef _AIX

#include <uinfo.h>

/* AIX limits */
#if defined(HAVE_GETUSERATTR) && !defined(S_UFSIZE_HARD) && defined(S_UFSIZE)
# define S_UFSIZE_HARD  S_UFSIZE "_hard"
# define S_UCPU_HARD  S_UCPU "_hard"
# define S_UDATA_HARD  S_UDATA "_hard"
# define S_USTACK_HARD  S_USTACK "_hard"
# define S_URSS_HARD  S_URSS "_hard"
# define S_UCORE_HARD  S_UCORE "_hard"
# define S_UNOFILE_HARD S_UNOFILE "_hard"
#endif

#if defined(HAVE_GETUSERATTR)
/*
 * AIX-specific login initialisation
 */
void 
set_limit(char *user, char *soft, char *hard, int resource, int mult)
{
        struct rlimit rlim;
        int slim, hlim;

        getrlimit(resource, &rlim);

        slim = 0;
        if (getuserattr(user, soft, &slim, SEC_INT) != -1) {
                if (slim < 0) {
                        rlim.rlim_cur = RLIM_INFINITY;
                } else if (slim != 0) {
                        /* See the wackiness below */
                        if (rlim.rlim_cur == slim * mult)
                                slim = 0;
                        else
                                rlim.rlim_cur = slim * mult;
                }
        }
        hlim = 0;
        if (getuserattr(user, hard, &hlim, SEC_INT) != -1) {
                if (hlim < 0) {
                        rlim.rlim_max = RLIM_INFINITY;
                } else if (hlim != 0) {
                        rlim.rlim_max = hlim * mult;
                }
        }

        /*
         * XXX For cpu and fsize the soft limit is set to the hard limit
         * if the hard limit is left at its default value and the soft limit
         * is changed from its default value, either by requesting it
         * (slim == 0) or by setting it to the current default.  At least
         * that's how rlogind does it.  If you're confused you're not alone.
         * Bug or feature? AIX 4.3.1.2
         */
        if ((!strcmp(soft, "fsize") || !strcmp(soft, "cpu"))
            && hlim == 0 && slim != 0)
                rlim.rlim_max = rlim.rlim_cur;
        /* A specified hard limit limits the soft limit */
        else if (hlim > 0 && rlim.rlim_cur > rlim.rlim_max)
                rlim.rlim_cur = rlim.rlim_max;
        /* A soft limit can increase a hard limit */
        else if (rlim.rlim_cur > rlim.rlim_max)
                rlim.rlim_max = rlim.rlim_cur;

        if (setrlimit(resource, &rlim) != 0)
                error("setrlimit(%.10s) failed: %.100s", soft, strerror(errno));
}

void 
set_limits_from_userattr(char *user)
{
        int mask;
        char buf[16];

        set_limit(user, S_UFSIZE, S_UFSIZE_HARD, RLIMIT_FSIZE, 512);
        set_limit(user, S_UCPU, S_UCPU_HARD, RLIMIT_CPU, 1);
        set_limit(user, S_UDATA, S_UDATA_HARD, RLIMIT_DATA, 512);
        set_limit(user, S_USTACK, S_USTACK_HARD, RLIMIT_STACK, 512);
        set_limit(user, S_URSS, S_URSS_HARD, RLIMIT_RSS, 512);
        set_limit(user, S_UCORE, S_UCORE_HARD, RLIMIT_CORE, 512);
#if defined(S_UNOFILE)
        set_limit(user, S_UNOFILE, S_UNOFILE_HARD, RLIMIT_NOFILE, 1);
#endif

        if (getuserattr(user, S_UMASK, &mask, SEC_INT) != -1) {
                /* Convert decimal to octal */
                (void) snprintf(buf, sizeof(buf), "%d", mask);
                if (sscanf(buf, "%o", &mask) == 1)
                        umask(mask);
        }
}
#endif /* defined(HAVE_GETUSERATTR) */

/*
 * AIX has a "usrinfo" area where logname and
 * other stuff is stored - a few applications
 * actually use this and die if it's not set
 */
void
aix_usrinfo(Session *s) 
{
	struct passwd *pw = s->pw;
	u_int i;
	const char *cp=NULL;

	if (s->ttyfd == -1)
		s->tty[0] = '\0';
	cp = xmalloc(22 + strlen(s->tty) + 2 * strlen(pw->pw_name));
	i = sprintf(cp, "LOGNAME=%s%cNAME=%s%cTTY=%s%c%c", pw->pw_name, 0, 
	    pw->pw_name, 0, s->tty, 0, 0);
	if (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);
	xfree(cp);
}

#endif /* _AIX */

