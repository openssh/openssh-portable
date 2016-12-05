/* $OpenBSD: scp.c,v 1.186 2016/05/25 23:48:45 schwarze Exp $ */
/*
 * scp - secure remote copy.  This is basically patched BSD rcp which
 * uses ssh to do the data transfer (instead of using rcmd).
 *
 * NOTE: This version should NOT be suid root.  (This uses ssh to
 * do the transfer and ssh has the necessary privileges.)
 *
 * 1995 Timo Rinne <tri@iki.fi>, Tatu Ylonen <ylo@cs.hut.fi>
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
 * Copyright (c) 1999 Aaron Campbell.  All rights reserved.
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

/*
 * Parts from:
 *
 * Copyright (c) 1983, 1990, 1992, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "includes.h"

#include <dirent.h>
#ifdef WINDOWS
#include <io.h>
#include <fcntl.h>
#include <Shlwapi.h>
#endif

#include <sys/types.h>
#include <sys/param.h>
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_POLL_H
#include <poll.h>
#else
# ifdef HAVE_SYS_POLL_H
#  include <sys/poll.h>
# endif
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <sys/wait.h>
#include <sys/uio.h>

#include <ctype.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#include <vis.h>
#endif

#include "xmalloc.h"
#include "atomicio.h"
#include "pathnames.h"
#include "log.h"
#include "misc.h"
#include "progressmeter.h"
#include "utf8.h"

extern char *__progname;

#define COPY_BUFLEN	16384

int do_cmd(char *host, char *remuser, char *cmd, int *fdin, int *fdout);
int do_cmd2(char *host, char *remuser, char *cmd, int fdin, int fdout);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
struct bwlimit bwlimit;

/* Name of current file being transferred. */
char *curfile;

/* This is set to non-zero to enable verbose mode. */
int verbose_mode = 0;

/* This is set to zero if the progressmeter is not desired. */
int showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
int throughlocal = 0;

/* This is the program to execute for the secured connection. ("ssh" or -S) */
char *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;


#ifdef WINDOWS
typedef BOOL bool;
#define false FALSE
#define true TRUE

#ifndef _SH_DENYNO
#define _SH_DENYNO 0x40
#endif

#define HAVE_UTIME_H

#ifdef HAVE_UTIME_H
#include <sys/utime.h>
#if defined(_NEXT_SOURCE) && !defined(_POSIX_SOURCE)
struct utimbuf {
  time_t actime;
  time_t modtime;
};
#endif /* _NEXT_SOURCE */
#else
struct utimbuf
{
  long actime;
  long modtime;
};
#endif

#ifndef _PATH_CP
#define _PATH_CP "copy"
//CHECK should we change in NT/2000 to copy ?? #define _PATH_CP "copy"
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif


/* This is set to non-zero to enable verbose mode. */
int scpverbose = 0;

#define SCP_STATISTICS_ENABLED
#define WITH_SCP_STATS
#define SCP_ALL_STATISTICS_ENABLED

/* This is set to non-zero to enable statistics mode. */
#ifdef SCP_STATISTICS_ENABLED
int statistics = 1;
#else /* SCP_STATISTICS_ENABLED */
int statistics = 0;
#endif /* SCP_STATISTICS_ENABLED */

/* This is set to non-zero to enable printing statistics for each file */
#ifdef SCP_ALL_STATISTICS_ENABLED
int all_statistics = 1;
#else /* SCP_ALL_STATISTICS_ENABLED */
int all_statistics = 0;
#endif /* SCP_ALL_STATISTICS_ENABLED */

/* This is set to non-zero if compression is desired. */
int compress = 0;

/* This is set to non-zero if running in batch mode (that is, password
   and passphrase queries are not allowed). */
int batchmode = 0;

/* This is to call ssh with argument -P (for using non-privileged
   ports to get through some firewalls.) */
int use_privileged_port = 1;

/* This is set to the cipher type string if given on the command line. */
char *cipher = NULL;

/* This is set to the RSA authentication identity file name if given on 
   the command line. */
char *identity = NULL;

/* This is the port to use in contacting the remote site (is non-NULL). */
char *port = NULL;

/* This is set password if given on the command line. */
char *password = NULL;

/* This is set ssh_config if given on the command line. */
char *ssh_config = NULL;

int ipv_restrict = 0;

#define ONLY_IPV4	1
#define ONLY_IPV6   2

#ifdef WITH_SCP_STATS

#define SOME_STATS_FILE stderr

#define ssh_max(a,b) (((a) > (b)) ? (a) : (b))

/*unsigned long*/ u_int64_t statbytes = 0;
DWORD stat_starttimems = 0;
time_t stat_starttime = 0;
time_t stat_lasttime = 0;
double ratebs = 0.0;

void stats_fixlen(int bytes);
//char *stat_eta(int secs);
char *stat_eta_new(int msecs);
#endif /* WITH_SCP_STATS */

/* Ssh options */
char **ssh_options = NULL;
size_t ssh_options_cnt = 0;
size_t ssh_options_alloc = 0;

// start: Windows specfic functions
#define S_ISDIR(x) (x & _S_IFDIR)

static int g_RootMode = 0;
#define M_ADMIN  4

CHAR	g_HomeDir[MAX_PATH];
CHAR	g_FSRoot[MAX_PATH];
int		isRootedPath = 0;  // set to 1 if we prepend a home root

int start_process_io(char *exename, char **argv, char **envv,
	HANDLE StdInput, HANDLE StdOutput, HANDLE StdError,
	unsigned long CreateFlags, PROCESS_INFORMATION  *pi,
	char *homedir, char *lpDesktop);

#ifdef WINDOWS
struct passwd pw;
char   username[128];

// InitForMicrosoftWindows() will initialize Unix like settings in Windows operating system.
int InitForMicrosoftWindows()
{
    int rc;
    struct passwd *pwd;

    /* Get user\'s passwd structure.  We need this for the home directory. */
    pwd = &pw ;
    rc = sizeof(username);
    if (GetUserName(username, (LPDWORD)&rc)) {
        pwd->pw_name = username;
    }
    else {
        return GetLastError();
    }

    return 0;
}

#endif

#define	EMSG	""
#define	BADCH	(int)'~'

int
sgetopt(int nargc,
	char * const *nargv,
	const char *ostr)
{
	static char *place = EMSG;		/* option letter processing */
	register char *oli;			/* option letter list index */
	char *p;
	extern char *optarg;
	extern int optind;
	extern int optopt;
	extern int opterr;

	if (!*place) 
	{				/* update scanning pointer */
		if (optind >= nargc ||  (*(place = nargv[optind]) != '-'))
		{
			place = EMSG;
			if (optind >= nargc )
				return(EOF);
			else
				return(BADCH);
		}
		if (place[1] && *++place == '-') 
		{	/* found "--" */
			++optind;
			place = EMSG;
			return(EOF);
		}
	}					/* option letter okay? */
	if ((optopt = (int)*place++) == (int)':' ||
	    !(oli = strchr((char *)ostr, optopt))) 
	{
		/*
		 * if the user didn't specify '-' as an option,
		 * assume it means EOF.
		 */
		if ((optopt == (int)'-'))
			return(EOF);
		if (!*place)
			++optind;
		if (opterr) 
		{
			if (!(p = strrchr(*nargv, '/')))
				p = *nargv;
			else
				++p;
			(void)fprintf(stderr, "%s: illegal option -- %c\n",
			    p, optopt);
		}
		return(BADCH);
	}
	if (*++oli != ':') 
	{			/* don't need argument */
		optarg = NULL;
		if (!*place)
			++optind;
	}
	else 
	{					/* need an argument */
		if (*place)			/* no white space */
			optarg = place;
		else if (nargc <= ++optind) 
		{	/* no arg */
			place = EMSG;
			if (!(p = strrchr(*nargv, '/')))
				p = *nargv;
			else
				++p;
			if (opterr)
				(void)fprintf(stderr,
				    "%s: option requires an argument -- %c\n",
				    p, optopt);
			return(BADCH);
		}
	 	else				/* white space */
			optarg = nargv[optind];
		place = EMSG;
		++optind;
	}
	return(optopt);				/* dump back option letter */
}

int _utimedir (char *name, struct _utimbuf *filetime)
{
   int rc, chandle;
	HANDLE	hFile;

	hFile = CreateFile( name,
							  GENERIC_WRITE,
						FILE_SHARE_READ,
						NULL,
						OPEN_EXISTING,
						FILE_FLAG_BACKUP_SEMANTICS,
						NULL );
	if ( hFile != INVALID_HANDLE_VALUE ) {
		chandle = _open_osfhandle ( (intptr_t)hFile, 0 );
		rc=_futime(chandle,filetime); // update access time to what we want
		_close(chandle);
		CloseHandle(hFile);
	}

	return rc;
}

// end of direntry functions
HANDLE hprocess=(HANDLE) 0; // we made it a global to stop child process(ssh) of scp
#else

#endif
static void
killchild(int signo)
{
	if (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		waitpid(do_cmd_pid, NULL, 0);
	}

	if (signo)
		_exit(1);
	exit(1);
}

static void
suspchild(int signo)
{
	int status;

	if (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo);
		while (waitpid(do_cmd_pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
		kill(getpid(), SIGSTOP);
	}
}

static int
do_local_cmd(arglist *a)
{
	u_int i;
	int status;
	pid_t pid;

	if (a->num == 0)
		fatal("do_local_cmd: no arguments");

	if (verbose_mode) {
		fprintf(stderr, "Executing:");
		for (i = 0; i < a->num; i++)
			fmprintf(stderr, " %s", a->list[i]);
		fprintf(stderr, "\n");
	}
#ifdef WINDOWS
	// flatten the cmd into a long space separated string and execute using system(cmd) api
	char cmdstr[2048] ;
	cmdstr[0] = '\0' ;
	for (i = 0; i < a->num; i++) {
		strcat (cmdstr, a->list[i]);
		strcat (cmdstr, " ");
	}
	if (system(cmdstr))
		return (-1); // failure executing
	return (0); // success
#else
	if ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	if (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	signal(SIGTERM, killchild);
	signal(SIGINT, killchild);
	signal(SIGHUP, killchild);

	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return (-1);

	return (0);
#endif
}

static int pipe_counter = 1;
/* create overlapped supported pipe */
BOOL CreateOverlappedPipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES sa, DWORD size) {
	HANDLE read_handle = INVALID_HANDLE_VALUE, write_handle = INVALID_HANDLE_VALUE;
	char pipe_name[MAX_PATH];

	/* create name for named pipe */
	if (-1 == sprintf_s(pipe_name, MAX_PATH, "\\\\.\\Pipe\\W32SCPPipe.%08x.%08x",
		GetCurrentProcessId(), pipe_counter++)) {
		debug("pipe - ERROR sprintf_s %d", errno);
		goto error;
	}

	read_handle = CreateNamedPipeA(pipe_name,
		PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_WAIT,
		1,
		4096,
		4096,
		0,
		sa);
	if (read_handle == INVALID_HANDLE_VALUE) {
		debug("pipe - CreateNamedPipe() ERROR:%d", errno);
		goto error;
	}

	/* connect to named pipe */
	write_handle = CreateFileA(pipe_name,
		GENERIC_WRITE,
		0,
		sa,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);
	if (write_handle == INVALID_HANDLE_VALUE) {
		debug("pipe - ERROR CreateFile() :%d", errno);
		goto error;
	}

	*hReadPipe = read_handle;
	*hWritePipe = write_handle;
	return TRUE;

error:
	if (read_handle)
		CloseHandle(read_handle);
	if (write_handle)
		CloseHandle(write_handle);

	return FALSE;

}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

int
do_cmd(char *host, char *remuser, char *cmd, int *fdin, int *fdout)
{
#ifdef WINDOWS
    size_t i, j;

    HANDLE hSaveStdout, hSaveStdin ; 
    HANDLE hstdout[2], hstdin[2] ;
    PROCESS_INFORMATION  pi;
    SECURITY_ATTRIBUTES sa ; /* simple */
    int rc; 
    HANDLE rfdfromssh, wfdtossh ;
    char *args[256];

    if (verbose_mode)
        fprintf(stderr, "Executing: host %s, user %s, command %s\n",
	        host, remuser ? remuser : "(unspecified)", cmd);

  // Child code in Windows OS will be a new created process of ssh.exe.
  // Child to execute the command on the remote host using ssh.

    i = 0;
    args[i++] = ssh_program;
    size_t	len;
    for(j = 0; j < ssh_options_cnt; j++) {
        args[i++] = "-o";

        //args[i++] = ssh_options[j];
        len = strlen(ssh_options[j])+3;

        args[i] = (char *) malloc(len); // add quotes
        strcpy_s(args[i],len, "\"");
        strcat_s(args[i],len, ssh_options[j]);
        strcat_s(args[i],len, "\"");
        i++ ;

        if (i > 250)
            fatal("Too many -o options (total number of arguments is more than 256)");
    }
    args[i++] = "-x";
    args[i++] = "-a";
    args[i++] = "\"-oFallBackToRsh no\""; // extra double quote needed for
										  // Windows platforms
    //7/2/2001 args[i++] = "\"-oClearAllForwardings yes\"";
    if (verbose_mode)
	    args[i++] = "-v";
    if (compress)
	    args[i++] = "-C";
    if (!use_privileged_port)
	    args[i++] = "-P";
    if (batchmode)
	    args[i++] = "\"-oBatchMode yes\"";
    if (password != NULL) {
		args[i++] = "-A";
		args[i++] = password;
	}
    if (cipher != NULL) {
		args[i++] = "-c";
		args[i++] = cipher;
	}
    if (identity != NULL) {
		args[i++] = "-i";
		args[i++] = identity;
	}
    if (port != NULL) {
		args[i++] = "-p";
		args[i++] = port;
	}
    if (ssh_config) {
        args[i++] = "-F";
        args[i++] = ssh_config;
    }
    if (remuser != NULL) {
		args[i++] = "-l";
		args[i++] = remuser;
	}

    if (ipv_restrict == ONLY_IPV4)
	    args[i++] = "-4";
    if (ipv_restrict == ONLY_IPV6)
	    args[i++] = "-6";

    args[i++] = host;
    args[i++] = cmd;
    args[i++] = NULL;

    // Create a pair of pipes for communicating with ssh
    // which we will spawn
    // Do the plumbing so that child ssh process to be spawned has its
    // standard input from the pout[0] and its standard output going to
    // pin[1]

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE ; /* pipe handles to be inherited */
    sa.lpSecurityDescriptor = NULL;
    /* command processor output redirected to a nameless pipe */

    rc = CreateOverlappedPipe( &hstdout[0], &hstdout[1], &sa, 0 ) ;
    /* read from this fd to get data from ssh.exe*/

    // make scp's pipe read handle not inheritable by ssh
    rc = DuplicateHandle(GetCurrentProcess(), hstdout[0], 
		GetCurrentProcess(), (PHANDLE) &rfdfromssh,
		0, // this parm ignored if DUPLICATE_SAME_ACCESS below
		FALSE, // not inherited
		DUPLICATE_SAME_ACCESS); 
    CloseHandle(hstdout[0]); // this CloseHandle() is a crucial must do
    hstdout[0] = rfdfromssh ;

    *fdin = _open_osfhandle((intptr_t)hstdout[0],0);
    _setmode (*fdin, O_BINARY); // set this file handle for binary I/O
    w32_allocate_fd_for_handle(hstdout[0], FALSE);

    rc = CreateOverlappedPipe( &hstdin[0], &hstdin[1], &sa, 0 ) ;
    /* write to this fd to get data into ssh.exe*/

    // make scp's pipe write handle not inheritable by ssh
    rc = DuplicateHandle(GetCurrentProcess(), hstdin[1], 
		GetCurrentProcess(), (PHANDLE) &wfdtossh,
		0, // this parm ignored if DUPLICATE_SAME_ACCESS below
		FALSE, // not inherited
		DUPLICATE_SAME_ACCESS); 
    CloseHandle(hstdin[1]); // this CloseHandle() is a crucial must do
    hstdin[1] = (HANDLE) wfdtossh ;

    *fdout = _open_osfhandle((intptr_t)hstdin[1],0);
    _setmode (*fdout, O_BINARY); // set this file handle for binary I/O
    w32_allocate_fd_for_handle(hstdin[1], FALSE);

    hSaveStdout = GetStdHandle(STD_OUTPUT_HANDLE); 
    //hSaveStderr = GetStdHandle(STD_ERROR_HANDLE); 
    hSaveStdin = GetStdHandle(STD_INPUT_HANDLE); 

    // Set a write handle to the pipe to be STDOUT. 
    SetStdHandle(STD_OUTPUT_HANDLE, hstdout[1]);
    // Set a write handle to the pipe to be STDERR. 
    //SetStdHandle(STD_ERROR_HANDLE, hstdout[1]);
    // Set a input handle to the pipe to be STDIN. 
    SetStdHandle(STD_INPUT_HANDLE, hstdin[0]);

    // start the child process(ssh)
    rc = start_process_io(
		NULL, /* executable name with .ext found in argv[0] */
		&args[0], /* argv */
		NULL ,
		hstdin[0], /* std input for cmd.exe */
		hstdout[1], /* std output for cmd.exe */
		GetStdHandle(STD_ERROR_HANDLE), //hstdout[1],  /* std error for cmd.exe */
		0, // dwStartupFlags,
		&pi,
		NULL, /* current directory is default directory we set before */
		NULL
	);

    if (port)
        free(port);

    if (cipher)
        free(cipher);

    if (identity)
        free(identity);

    if (ssh_config)
        free(ssh_config);

    if (!rc) {
	    printf("%s could not be started\n", ssh_program);
	    exit(1);
    }
    else {
	    hprocess = pi.hProcess ;
    }

    // After process creation, restore the saved STDOUT and STDERR. 
    SetStdHandle(STD_OUTPUT_HANDLE, hSaveStdout);
    //SetStdHandle(STD_ERROR_HANDLE, hSaveStderr);
    SetStdHandle(STD_INPUT_HANDLE, hSaveStdin);

    /* now close the pipe's side that the ssh.exe will use as write handle */
    CloseHandle(hstdout[1]) ;
    /* now close the pipe's side that the ssh.exe will use as read handle */
    CloseHandle(hstdin[0]) ;

  // update passed variables with where other funstions should read and write
  // from to get I/O from above child process over pipe.

  //*fdout = remout;
  //*fdin =  remin;

    return 0;
#else
	int pin[2], pout[2], reserved[2];

	if (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	/*
	 * Reserve two descriptors so that the real pipes won't get
	 * descriptors 0 and 1 because that will screw up dup2 below.
	 */
	if (pipe(reserved) < 0)
		fatal("pipe: %s", strerror(errno));

	/* Create a socket pair for communicating with ssh. */
	if (pipe(pin) < 0)
		fatal("pipe: %s", strerror(errno));
	if (pipe(pout) < 0)
		fatal("pipe: %s", strerror(errno));

	/* Free the reserved descriptors. */
	close(reserved[0]);
	close(reserved[1]);

	signal(SIGTSTP, suspchild);
	signal(SIGTTIN, suspchild);
	signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	do_cmd_pid = fork();
	if (do_cmd_pid == 0) {
		/* Child. */
		close(pin[1]);
		close(pout[0]);
		dup2(pin[0], 0);
		dup2(pout[1], 1);
		close(pin[0]);
		close(pout[1]);

		replacearg(&args, 0, "%s", ssh_program);
		if (remuser != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(ssh_program, args.list);
		perror(ssh_program);
		exit(1);
	} else if (do_cmd_pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	/* Parent.  Close the other side, and return the local side. */
	close(pin[0]);
	*fdout = pin[1];
	close(pout[1]);
	*fdin = pout[0];
	signal(SIGTERM, killchild);
	signal(SIGINT, killchild);
	signal(SIGHUP, killchild);
	return 0;
#endif
}

/*
 * This functions executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
int
do_cmd2(char *host, char *remuser, char *cmd, int fdin, int fdout)
{
#ifndef WIN32_FIXME
	pid_t pid;
	int status;

	if (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	if (pid == 0) {
		dup2(fdin, 0);
		dup2(fdout, 1);

		replacearg(&args, 0, "%s", ssh_program);
		if (remuser != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(ssh_program, args.list);
		perror(ssh_program);
		exit(1);
	} else if (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
#endif
	return 0;
}

typedef struct {
	size_t cnt;
	char *buf;
} BUF;

BUF *allocbuf(BUF *, int, int);
void lostconn(int);
int okname(char *);
void run_err(const char *,...);
void verifydir(char *);

struct passwd *pwd;
uid_t userid;
int errs, remin, remout;
int pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
char cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

int response(void);
void rsource(char *, struct stat *);
void sink(int, char *[]);
void source(int, char *[]);
void tolocal(int, char *[]);
void toremote(char *, int, char *[]);
void usage(void);

int
main(int argc, char **argv)
{
	int ch, fflag, tflag, status, n;
	char *targ, **newargv;
	const char *errstr;
	extern char *optarg;
	extern int optind;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	setlocale(LC_CTYPE, "");

	/* Copy argv, because we modify it */
	newargv = xcalloc(MAX(argc + 1, 1), sizeof(*newargv));
	for (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	memset(&args, '\0', sizeof(args));
	memset(&remote_remote_args, '\0', sizeof(remote_remote_args));
	args.list = remote_remote_args.list = NULL;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "\"-oForwardAgent no\"");
	addargs(&args, "\"-oPermitLocalCommand no\"");
	addargs(&args, "\"-oClearAllForwardings yes\"");

	fflag = tflag = 0;
	while ((ch = getopt(argc, argv, "dfl:prtvBCc:i:P:q12346S:o:F:")) != -1)
		switch (ch) {
		/* User-visible flags. */
		case '1':
		case '2':
		case '4':
            ipv_restrict = ONLY_IPV4;
            break;
		case '6':
            ipv_restrict = ONLY_IPV6;
            break;
		case 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
            compress = ch;
			break;
		case '3':
			throughlocal = 1;
			break;
		case 'o':
            addargs(&remote_remote_args, "-%c", ch);
            addargs(&remote_remote_args, "%s", optarg);
            addargs(&args, "-%c", ch);
            addargs(&args, "%s", optarg);
            break;
        case 'c':
            addargs(&remote_remote_args, "-%c", ch);
            addargs(&remote_remote_args, "%s", optarg);
            addargs(&args, "-%c", ch);
            addargs(&args, "%s", optarg);

            cipher = xstrdup(optarg);;
            break;
		case 'i':
            addargs(&remote_remote_args, "-%c", ch);
            addargs(&remote_remote_args, "%s", optarg);
            addargs(&args, "-%c", ch);
            addargs(&args, "%s", optarg);

            identity = xstrdup(optarg);;
            break;
		case 'F':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
            
            ssh_config = xstrdup(optarg);;
            break;
		case 'P':
			addargs(&remote_remote_args, "-p");
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-p");
			addargs(&args, "%s", optarg);

            port = xstrdup(optarg);;
			break;
		case 'B':
			addargs(&remote_remote_args, "\"-oBatchmode yes\"");
			addargs(&args, "\"-oBatchmode yes\"");

            batchmode = 1;
			break;
		case 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			if (errstr != NULL)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			break;
		case 'p':
			pflag = 1;
			break;
		case 'r':
			iamrecursive = 1;
			break;
		case 'S':
			ssh_program = xstrdup(optarg);
			break;
		case 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			verbose_mode = 1;
			break;
		case 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			break;

		/* Server options. */
		case 'd':
			targetshouldbedirectory = 1;
			break;
		case 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			break;
		case 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_BINARY);
#endif
			break;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

#ifndef WINDOWS
	if ((pwd = getpwuid(userid = getuid())) == NULL)
		fatal("unknown user %u", (u_int) userid);
#else
	InitForMicrosoftWindows(); // picks the username, user home dir
#endif

	if (!isatty(STDOUT_FILENO))
		showprogress = 0;

	if (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} else {
		if (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	if (fflag) {
		/* Follow "protocol", send data. */
		(void) response();
		source(argc, argv);
		exit(errs != 0);
	}
	if (tflag) {
		/* Receive data. */
		sink(argc, argv);
		exit(errs != 0);
	}
	if (argc < 2)
		usage();
	if (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(void) snprintf(cmd, sizeof cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	#ifndef WINDOWS
	(void) signal(SIGPIPE, lostconn);
	#endif

	if ((targ = colon(argv[argc - 1])))	/* Dest is remote host. */
		toremote(targ, argc, argv);
	else {
		if (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
#ifndef WINDOWS
	if (do_cmd_pid != -1 && errs == 0) {
		if (remin != -1)
		    (void) close(remin);
		if (remout != -1)
		    (void) close(remout);
		if (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		else {
			if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
#endif
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
static int
scpio(void *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	if (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	return 0;
}

static int
do_times(int fd, int verb, const struct stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	char buf[(20 + 7 + 2) * 2 + 2];

	(void)snprintf(buf, sizeof(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	if (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(void) atomicio(vwrite, fd, buf, strlen(buf));
	return (response());
}

void
toremote(char *targ, int argc, char **argv)
{
	char *bp, *host, *src, *suser, *thost, *tuser, *arg;
	arglist alist;
	int i;
	u_int j;

	memset(&alist, '\0', sizeof(alist));
	alist.list = NULL;

	*targ++ = 0;
	if (*targ == 0)
		targ = ".";

	arg = xstrdup(argv[argc - 1]);
	if ((thost = strrchr(arg, '@'))) {
		/* user@host */
		*thost++ = 0;
		tuser = arg;
		if (*tuser == '\0')
			tuser = NULL;
	} else {
		thost = arg;
		tuser = NULL;
	}

	if (tuser != NULL && !okname(tuser)) {
		free(arg);
		return;
	}

	for (i = 0; i < argc - 1; i++) {
		src = colon(argv[i]);
		if (src && throughlocal) {	/* extended remote to remote */
			*src++ = 0;
			if (*src == 0)
				src = ".";
			host = strrchr(argv[i], '@');
			if (host) {
				*host++ = 0;
				host = cleanhostname(host);
				suser = argv[i];
				if (*suser == '\0')
					suser = pwd->pw_name;
				else if (!okname(suser))
					continue;
			} else {
				host = cleanhostname(argv[i]);
				suser = NULL;
			}
			xasprintf(&bp, "%s -f %s%s", cmd,
			    *src == '-' ? "-- " : "", src);
			if (do_cmd(host, suser, bp, &remin, &remout) < 0)
				exit(1);
			free(bp);
			host = cleanhostname(thost);
			xasprintf(&bp, "%s -t %s%s", cmd,
			    *targ == '-' ? "-- " : "", targ);
			if (do_cmd2(host, tuser, bp, remin, remout) < 0)
				exit(1);
			free(bp);
			(void) close(remin);
			(void) close(remout);
			remin = remout = -1;
		} else if (src) {	/* standard remote to remote */
			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-\"oClearAllForwardings yes\"");
			addargs(&alist, "-n");
			for (j = 0; j < remote_remote_args.num; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}
			*src++ = 0;
			if (*src == 0)
				src = ".";
			host = strrchr(argv[i], '@');

			if (host) {
				*host++ = 0;
				host = cleanhostname(host);
				suser = argv[i];
				if (*suser == '\0')
					suser = pwd->pw_name;
				else if (!okname(suser))
					continue;
				addargs(&alist, "-l");
				addargs(&alist, "%s", suser);
			} else {
				host = cleanhostname(argv[i]);
			}
			addargs(&alist, "--");
			addargs(&alist, "%s", host);
			addargs(&alist, "%s", cmd);
			addargs(&alist, "%s", src);
			addargs(&alist, "%s%s%s:%s",
			    tuser ? tuser : "", tuser ? "@" : "",
			    thost, targ);
			if (do_local_cmd(&alist) != 0)
				errs = 1;
		} else {	/* local to remote */
			if (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				host = cleanhostname(thost);
				if (do_cmd(host, tuser, bp, &remin,
				    &remout) < 0)
					exit(1);
				if (response() < 0)
					exit(1);
				free(bp);
			}
			source(1, argv + i);
		}
	}
	free(arg);
}

void
tolocal(int argc, char **argv)
{
	char *bp, *host, *src, *suser;
	arglist alist;
	int i;

	memset(&alist, '\0', sizeof(alist));
	alist.list = NULL;

	for (i = 0; i < argc - 1; i++) {
		if (!(src = colon(argv[i]))) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			if (iamrecursive)
				addargs(&alist, "-r");
			if (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			if (do_local_cmd(&alist))
				++errs;
			continue;
		}
		*src++ = 0;
		if (*src == 0)
			src = ".";
		if ((host = strrchr(argv[i], '@')) == NULL) {
			host = argv[i];
			suser = NULL;
		} else {
			*host++ = 0;
			suser = argv[i];
			if (*suser == '\0')
				suser = pwd->pw_name;
		}
		host = cleanhostname(host);
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		if (do_cmd(host, suser, bp, &remin, &remout) < 0) {
			free(bp);
			++errs;
			continue;
		}
		free(bp);
		sink(1, argv + argc - 1);
		(void) close(remin);
		remin = remout = -1;
	}
}

void
source(int argc, char **argv)
{
	struct stat stb;
	static BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	int fd = -1, haderr, indx;
	char *last = NULL, *lastf = NULL, *lastr = NULL, *name, buf[2048], encname[PATH_MAX];
	int len;

	for (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		while (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		if ((fd = open(name, O_RDONLY|O_NONBLOCK, 0)) < 0)
			goto syserr;
		if (strchr(name, '\n') != NULL) {
			strnvis(encname, name, sizeof(encname), VIS_NL);
			name = encname;
		}
		if (fstat(fd, &stb) < 0) {
syserr:			run_err("%s: %s", name, strerror(errno));
			goto next;
		}
		if (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			goto next;
		}
		unset_nonblock(fd);
		switch (stb.st_mode & S_IFMT) {
		case S_IFREG:
			break;
		case S_IFDIR:
			if (iamrecursive) {
				rsource(name, &stb);
				goto next;
			}
			/* FALLTHROUGH */
		default:
			run_err("%s: not a regular file", name);
			goto next;
		}
#ifdef WINDOWS
		if ((lastf = strrchr(name, '/')) == NULL && (lastr = strrchr(name, '\\')) == NULL)
			last = name;
        else {
            if (lastf)
                last = lastf;
            if (lastr)
                last = lastr;
            ++last;
        }
#else
        if ((last = strrchr(name, '/')) == NULL)
            last = name;
        else
            ++last;
#endif
		curfile = last;
		if (pflag) {
			if (do_times(remout, verbose_mode, &stb) < 0)
				goto next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, sizeof buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		if (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(void) atomicio(vwrite, remout, buf, strlen(buf));
		if (response() < 0)
			goto next;
		if ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == NULL) {
next:			if (fd != -1) {
				(void) close(fd);
				fd = -1;
			}
			continue;
		}
		if (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		for (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			if (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			if (!haderr) {
				if ((nr = atomicio(read, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			if (haderr) {
				(void)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				continue;
			}
			if (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		if (fd != -1) {
			if (close(fd) < 0 && !haderr)
				haderr = errno;
			fd = -1;
		}
		if (!haderr)
			(void) atomicio(vwrite, remout, "", 1);
		else
			run_err("%s: %s", name, strerror(haderr));
		(void) response();
		if (showprogress)
			stop_progress_meter();
	}
}

void
rsource(char *name, struct stat *statp)
{
	DIR *dirp;
	struct dirent *dp;
	char *last, *vect[1], path[PATH_MAX];

	if (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		return;
	}
	last = strrchr(name, '/');
	if (last == NULL)
		last = name;
	else
		last++;
	if (pflag) {
		if (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			return;
		}
	}
	(void) snprintf(path, sizeof path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	if (verbose_mode)
#ifdef WINDOWS
        {
            printf("Entering directory: ");
            wchar_t* wtmp = utf8_to_utf16(path);
            WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), wtmp, wcslen(wtmp), 0, 0);
            free(wtmp);
        }
#else
        fmprintf(stderr, "Entering directory: %s", path);
#endif

	(void) atomicio(vwrite, remout, path, strlen(path));
	if (response() < 0) {
		closedir(dirp);
		return;
	}
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_ino == 0)
			continue;
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		if (strlen(name) + 1 + strlen(dp->d_name) >= sizeof(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			continue;
		}
		(void) snprintf(path, sizeof path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(void) closedir(dirp);
	(void) atomicio(vwrite, remout, "E\n", 2);
	(void) response();
}

void
sink(int argc, char **argv)
{
	static BUF buffer;
	struct stat stb;
	enum {
		YES, NO, DISPLAYED
	} wrerr;
	BUF *bp;
	off_t i;
	size_t j, count;
	int amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	int setimes, targisdir, wrerrno = 0;
	char ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	struct timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; goto screwup; }

	setimes = targisdir = 0;
	mask = umask(0);
	if (!pflag)
		(void) umask(mask);
	if (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	if (targetshouldbedirectory)
		verifydir(targ);

	(void) atomicio(vwrite, remout, "", 1);
	if (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	for (first = 1;; first = 0) {
		cp = buf;
		if (atomicio(read, remin, cp, 1) != 1)
			return;
		if (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		do {
			if (atomicio(read, remin, &ch, sizeof(ch)) != sizeof(ch))
				SCREWUP("lost connection");
			*cp++ = ch;
		} while (cp < &buf[sizeof(buf) - 1] && ch != '\n');
		*cp = 0;
		if (verbose_mode)
#ifdef WINDOWS
            {
                printf("Sink: ");
                wchar_t* wtmp = utf8_to_utf16(buf);
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), wtmp, wcslen(wtmp), 0, 0);
                free(wtmp);
            }
#else
            fmprintf(stderr, "Sink: %s", buf);
#endif
		if (buf[0] == '\01' || buf[0] == '\02') {
			if (iamremote == 0) {
				(void) snmprintf(visbuf, sizeof(visbuf),
				    NULL, "%s", buf + 1);
				(void) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			if (buf[0] == '\02')
				exit(1);
			++errs;
			continue;
		}
		if (buf[0] == 'E') {
			(void) atomicio(vwrite, remout, "", 1);
			return;
		}
		if (ch == '\n')
			*--cp = 0;

		cp = buf;
		if (*cp == 'T') {
			setimes++;
			cp++;
			if (!isdigit((unsigned char)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			if (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			if ((time_t)ull < 0 ||
			    (unsigned long long)(time_t)ull != ull)
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			if (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			if (!isdigit((unsigned char)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			if (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			if ((time_t)ull < 0 ||
			    (unsigned long long)(time_t)ull != ull)
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			if (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(void) atomicio(vwrite, remout, "", 1);
			continue;
		}
		if (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			if (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		for (++cp; cp < buf + 5; cp++) {
			if (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		if (*cp++ != ' ')
			SCREWUP("mode not delimited");

		for (size = 0; isdigit((unsigned char)*cp);)
			size = size * 10 + (*cp++ - '0');
		if (*cp++ != ' ')
			SCREWUP("size not delimited");
		if ((strchr(cp, '/') != NULL) || (strcmp(cp, "..") == 0)) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		if (targisdir) {
			static char *namebuf;
			static size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			if (need > cursize) {
				free(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(void) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} else
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		if (buf[0] == 'D') {
			int mod_flag = pflag;
			if (!iamrecursive)
				SCREWUP("received directory without -r");
			if (exists) {
				if (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					goto bad;
				}
				if (pflag)
					(void) chmod(np, mode);
			} else {
				/* Handle copying from a read-only
				   directory */
				mod_flag = 1;
				if (mkdir(np, mode | S_IRWXU) < 0)
					goto bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect);
			if (setimes) {
				setimes = 0;
				if (utimes(vect[0], tv) < 0)
					run_err("%s: set times: %s",
					    vect[0], strerror(errno));
			}
			if (mod_flag)
				(void) chmod(vect[0], mode);
			free(vect[0]);
			continue;
		}
		omode = mode;
		mode |= S_IWUSR;
		if ((ofd = open(np, O_WRONLY|O_CREAT, mode)) < 0) {
bad:			run_err("%s: %s", np, strerror(errno));
			continue;
		}
		(void) atomicio(vwrite, remout, "", 1);
		if ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == NULL) {
			(void) close(ofd);
			continue;
		}
		cp = bp->buf;
		wrerr = NO;

		statbytes = 0;
		if (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		for (count = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			if (i + amt > size)
				amt = size - i;
			count += amt;
			do {
				j = atomicio6(read, remin, cp, amt,
				    scpio, &statbytes);
				if (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} while (amt > 0);

			if (count == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				if (wrerr == NO) {
					if (atomicio(vwrite, ofd, bp->buf,
					    count) != count) {
						wrerr = YES;
						wrerrno = errno;
					}
				}
				count = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		if (count != 0 && wrerr == NO &&
		    atomicio(vwrite, ofd, bp->buf, count) != count) {
			wrerr = YES;
			wrerrno = errno;
		}
		if (wrerr == NO && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0) {
			run_err("%s: truncate: %s", np, strerror(errno));
			wrerr = DISPLAYED;
		}
		if (pflag) {
			if (exists || omode != mode)
#ifdef HAVE_FCHMOD
				if (fchmod(ofd, omode)) {
#else /* HAVE_FCHMOD */
				if (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					run_err("%s: set mode: %s",
					    np, strerror(errno));
					wrerr = DISPLAYED;
				}
		} else {
			if (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				if (fchmod(ofd, omode & ~mask)) {
#else /* HAVE_FCHMOD */
				if (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					run_err("%s: set mode: %s",
					    np, strerror(errno));
					wrerr = DISPLAYED;
				}
		}
		if (close(ofd) == -1) {
			wrerr = YES;
			wrerrno = errno;
		}
		(void) response();
		if (showprogress)
			stop_progress_meter();
		if (setimes && wrerr == NO) {
			setimes = 0;
			if (utimes(np, tv) < 0) {
				run_err("%s: set times: %s",
				    np, strerror(errno));
				wrerr = DISPLAYED;
			}
		}
		switch (wrerr) {
		case YES:
			run_err("%s: %s", np, strerror(wrerrno));
			break;
		case NO:
			(void) atomicio(vwrite, remout, "", 1);
			break;
		case DISPLAYED:
			break;
		}
	}
screwup:
	run_err("protocol error: %s", why);
	exit(1);
}

int
response(void)
{
	char ch, *cp, resp, rbuf[2048], visbuf[2048];

	if (atomicio(read, remin, &resp, sizeof(resp)) != sizeof(resp))
		lostconn(0);

	cp = rbuf;
	switch (resp) {
	case 0:		/* ok */
		return (0);
	default:
		*cp++ = resp;
		/* FALLTHROUGH */
	case 1:		/* error, followed by error msg */
	case 2:		/* fatal error, "" */
		do {
			if (atomicio(read, remin, &ch, sizeof(ch)) != sizeof(ch))
				lostconn(0);
			*cp++ = ch;
		} while (cp < &rbuf[sizeof(rbuf) - 1] && ch != '\n');

		if (!iamremote) {
			cp[-1] = '\0';
			(void) snmprintf(visbuf, sizeof(visbuf),
			    NULL, "%s\n", rbuf);
			(void) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		if (resp == 1)
			return (-1);
		exit(1);
	}
	/* NOTREACHED */
}

void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: scp [-12346BCpqrv] [-c cipher] [-F ssh_config] [-i identity_file]\n"
	    "           [-l limit] [-o ssh_option] [-P port] [-S program]\n"
	    "           [[user@]host1:]file1 ... [[user@]host2:]file2\n");
	exit(1);
}

void
run_err(const char *fmt,...)
{
	static FILE *fp;
	va_list ap;

	++errs;
	if (fp != NULL || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(void) fprintf(fp, "%c", 0x01);
		(void) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(void) vfprintf(fp, fmt, ap);
		va_end(ap);
		(void) fprintf(fp, "\n");
		(void) fflush(fp);
	}

	if (!iamremote) {
		va_start(ap, fmt);
		vfmprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
}

void
verifydir(char *cp)
{
	struct stat stb;

	if (!stat(cp, &stb)) {
		if (S_ISDIR(stb.st_mode))
			return;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

int
okname(char *cp0)
{
	int c;
	char *cp;

	cp = cp0;
	do {
		c = (int)*cp;
		if (c & 0200)
			goto bad;
		if (!isalpha(c) && !isdigit((unsigned char)c)) {
			switch (c) {
			case '\'':
			case '"':
			case '`':
			case ' ':
			case '#':
				goto bad;
			default:
				break;
			}
		}
	} while (*++cp);
	return (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	return (0);
}

BUF *
allocbuf(BUF *bp, int fd, int blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	struct stat stb;

	if (fstat(fd, &stb) < 0) {
		run_err("fstat: %s", strerror(errno));
		return (0);
	}
	size = roundup(stb.st_blksize, blksize);
	if (size == 0)
		size = blksize;
#else /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	if (bp->cnt >= size)
		return (bp);
	if (bp->buf == NULL)
		bp->buf = xmalloc(size);
	else
		bp->buf = xreallocarray(bp->buf, 1, size);
	memset(bp->buf, 0, size);
	bp->cnt = size;
	return (bp);
}

void
lostconn(int signo)
{
	if (!iamremote)
		(void)write(STDERR_FILENO, "lost connection\n", 16);
	if (signo)
		_exit(1);
	else
		exit(1);
}
#ifdef WINDOWS
/* start_process_io()
input parameters:
	exename - name of executable
	StdXXXX - the three stdin, stdout, stdout I/O handles.
*/

int start_process_io(char *exename, char **argv, char **envv,
	HANDLE StdInput, HANDLE StdOutput, HANDLE StdError,
	unsigned long CreateFlags, PROCESS_INFORMATION  *pi,
	char *homedir, char *lpDesktop)
{
	UNREFERENCED_PARAMETER(envv);
	STARTUPINFOW          sui;
	DWORD ret;
	char cmdbuf[2048];
	int ctr;

	/* set up the STARTUPINFO structure,
	*  then call CreateProcess to try and start the new exe.
	*/
	sui.cb = sizeof(STARTUPINFOW);
	sui.lpReserved = 0;
	sui.lpDesktop = utf8_to_utf16(lpDesktop);
        sui.lpTitle = NULL; /* NULL means use exe name as title */
	sui.dwX = 0;
	sui.dwY = 0;
	sui.dwXSize = 132;
	sui.dwYSize = 60;
	sui.dwXCountChars = 132;
	sui.dwYCountChars = 60;
	sui.dwFillAttribute = 0;
	sui.dwFlags = STARTF_USESTDHANDLES | STARTF_USESIZE | STARTF_USECOUNTCHARS; // | STARTF_USESHOWWINDOW ;
	sui.wShowWindow = 0; // FALSE ;
	sui.cbReserved2 = 0;
	sui.lpReserved2 = 0;
	sui.hStdInput = (HANDLE)StdInput;
	sui.hStdOutput = (HANDLE)StdOutput;
	sui.hStdError = (HANDLE)StdError;

	ctr = 0;
	cmdbuf[0] = '\0';
        if (argv[0][0] != '\0' && argv[0][1] != ':') {
                strcat(cmdbuf, w32_programdir());
                strcat(cmdbuf, "\\");
        }
	while (argv[ctr]) {
		strcat_s(cmdbuf, sizeof(cmdbuf), argv[ctr]);
		strcat_s(cmdbuf, sizeof(cmdbuf), " ");
		ctr++;
	}

    ret = CreateProcessW(
        utf8_to_utf16(exename), // given in form like "d:\\util\\cmd.exe"
        utf8_to_utf16(cmdbuf), /* in "arg0 arg1 arg2" form command line */
        NULL, /* process security */
        NULL, /* thread security */
        TRUE, /* inherit handles is YES */
        CreateFlags,
        /* give new proc a new screen, suspend it for debugging also */
        NULL, /* in "E1=a0E2=b0E3=c00" form environment,
              NULL means use parent's */
        utf8_to_utf16(homedir), /* Current Directory, NULL means use whats for parent */
        &sui, /* start up info */
        pi); /* process created info kept here */

	if (ret == TRUE) {
		//cprintf ( "Process created, pid=%d, threadid=%d\n",pi->dwProcessId,
		//			  pi->dwThreadId ) ;

		return pi->dwProcessId;

	}
	else {
		/* report failure to the user. */
		return ret;
	}
}
#endif
