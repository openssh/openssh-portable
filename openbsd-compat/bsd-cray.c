/*
 * The modules contains code to support cray t3e and sv1 computers.
 * It is here to minimize the modifcations to the openssh base code.
 */

#ifdef _CRAY

#include <udb.h>
#include <tmpdir.h>
#include <unistd.h>
#include <sys/category.h>
#include <utmp.h>
#include <sys/jtab.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <pwd.h>
#include <fcntl.h>
#include <errno.h>

char cray_tmpdir[TPATHSIZ+1];               /* job TMPDIR path */

/*
 * Functions.
 */
int cray_setup(uid_t, char *);
void cray_retain_utmp(struct utmp *, int);
void cray_create_tmpdir(int, uid_t, gid_t);
void cray_delete_tmpdir(char *, int , uid_t);
void cray_job_termination_handler (int);
void cray_init_job(struct passwd *);
void cray_set_tmpdir(struct utmp *);

/* 
 * Orignal written by:
 *     Wayne Schroeder
 *     San Diego Supercomputer Center
 *     schroeder@sdsc.edu
*/
int 
cray_setup(uid_t uid, char *username)
{
  	struct udb *p;
  	extern struct udb *getudb();
	extern char *setlimits();
  	int i, j;
  	int accts[MAXVIDS];
  	int naccts;
  	int err;
  	char *sr;
  	int pid;
  	struct jtab jbuf;
  	int jid;

  	if ((jid = getjtab (&jbuf)) < 0) {
		debug("getjtab");
		return -1;
	}

  	/* Find all of the accounts for a particular user */
  	err = setudb();    /* open and rewind the Cray User DataBase */
  	if(err != 0) {
      		debug("UDB open failure");
      		return -1;
    	}
  	naccts = 0;
  	while ((p = getudb()) != UDB_NULL) {
      		if (p->ue_uid == -1) break;
      		if(uid == p->ue_uid) {
          		for(j = 0; p->ue_acids[j] != -1 && j < MAXVIDS; j++) {
              			accts[naccts] = p->ue_acids[j];
              			naccts++;
            		}
        	}
    	}
  	endudb();        /* close the udb */
  	if (naccts == 0 || accts[0] == 0) {
      		debug("No Cray accounts found");
      		return -1;
    	}
 
  	/* Perhaps someday we'll prompt users who have multiple accounts
     	   to let them pick one (like CRI's login does), but for now just set 
     	   the account to the first entry. */
  	if (acctid(0, accts[0]) < 0) {
      		debug("System call acctid failed, accts[0]=%d",accts[0]);
      		return -1;
    	}
 
	/* Now set limits, including CPU time for the (interactive) job and process,
     	   and set up permissions (for chown etc), etc.  This is via an internal CRI
     	   routine, setlimits, used by CRI's login. */

  	pid = getpid();
  	sr = setlimits(username, C_PROC, pid, UDBRC_INTER);
  	if (sr != NULL) {
      		debug("%.200s", sr);
      		return -1;
    	}
  	sr = setlimits(username, C_JOB, jid, UDBRC_INTER);
  	if (sr != NULL) {
      		debug("%.200s", sr);
      		return -1;
    	}

  	return 0;
}


/*
 *  Retain utmp/wtmp information - used by cray accounting.
 */
void
cray_retain_utmp(struct utmp *ut, int pid)
{
	int fd;
        struct utmp utmp;

	if ((fd = open(UTMP_FILE, O_RDONLY)) >= 0) {
       		while (read(fd, (char *)&utmp, sizeof(utmp)) == sizeof(utmp)) {
                	if (pid == utmp.ut_pid) {
                         	ut->ut_jid = utmp.ut_jid;
                         	strncpy(ut->ut_tpath, utmp.ut_tpath, TPATHSIZ);
                         	strncpy(ut->ut_host, utmp.ut_host, strlen(utmp.ut_host));
                         	strncpy(ut->ut_name, utmp.ut_name, strlen(utmp.ut_name));
			 	break;
			}
		}
		close(fd);
	} 
}

/*
 * tmpdir support.
 */

/*
 * find and delete jobs tmpdir.
 */
void
cray_delete_tmpdir(char *login, int jid, uid_t uid)
{
	int child;
        static char jtmp[TPATHSIZ];
       	struct stat statbuf;
        int c;
       	int wstat;

        for (c = 'a'; c <= 'z'; c++) {
         	snprintf(jtmp, TPATHSIZ, "%s/jtmp.%06d%c", JTMPDIR, jid, c);
               	if (stat(jtmp, &statbuf) == 0 && statbuf.st_uid == uid) break;
       	}

       	if (c > 'z') return;

       	if ((child = fork()) == 0) {
       		execl(CLEANTMPCMD, CLEANTMPCMD, login, jtmp, 0);
               	fatal("ssh_cray_rmtmpdir: execl of CLEANTMPCMD failed");
       	}

	while (waitpid (child, &wstat, 0) == -1 && errno == EINTR);
}

/*
 * Remove tmpdir on job termination.
 */
void
cray_job_termination_handler (int sig)
{
	int jid;
	char *login = NULL;
	struct jtab jtab;

	debug("Received SIG JOB.");

	if ((jid = waitjob(&jtab)) == -1 ||
	    (login = uid2nam(jtab.j_uid)) == NULL) return;

	cray_delete_tmpdir(login, jid, jtab.j_uid);
}


/*
 * Set job id and create tmpdir directory.
 */
void    
cray_init_job(struct passwd *pw)
{       
        int jid;
        int c;

        jid = setjob(pw->pw_uid, WJSIGNAL);
        if (jid < 0) fatal("System call setjob failure");

        for (c = 'a'; c <= 'z'; c++) {
                snprintf(cray_tmpdir, TPATHSIZ, "%s/jtmp.%06d%c", JTMPDIR, jid, c);
                if (mkdir(cray_tmpdir,  JTMPMODE) != 0) continue;
                if (chown(cray_tmpdir,  pw->pw_uid, pw->pw_gid) != 0) {
                        rmdir(cray_tmpdir);
                        continue;
                }
                break;
        }

        if (c > 'z') cray_tmpdir[0] = '\0';
}               

void
cray_set_tmpdir(struct utmp *ut)
{       
  	int jid;
  	struct jtab jbuf;

  	if ((jid = getjtab (&jbuf)) < 0) return;

	/*
	 * Set jid and tmpdir in utmp record.
  	 */
	ut->ut_jid = jid;
	strncpy(ut->ut_tpath, cray_tmpdir, TPATHSIZ);
}       

#endif
