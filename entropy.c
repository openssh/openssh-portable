/*
 * Copyright (c) 2000 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Markus Friedl.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#include "ssh.h"
#include "xmalloc.h"

#include <openssl/rand.h>
#include <openssl/sha.h>

/* SunOS 4.4.4 needs this */
#ifdef HAVE_FLOATINGPOINT_H
# include <floatingpoint.h>
#endif /* HAVE_FLOATINGPOINT_H */

RCSID("$Id: entropy.c,v 1.18 2000/07/15 04:59:15 djm Exp $");

#ifndef offsetof
# define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

/* Print lots of detail */
/* #define DEBUG_ENTROPY */

/* Number of times to pass through command list gathering entropy */
#define NUM_ENTROPY_RUNS	1

/* Scale entropy estimates back by this amount on subsequent runs */
#define SCALE_PER_RUN		10.0

/* Minimum number of commands to be considered valid */
#define MIN_ENTROPY_SOURCES 16

#define WHITESPACE " \t\n"

#ifndef RUSAGE_SELF
# define RUSAGE_SELF 0
#endif
#ifndef RUSAGE_CHILDREN
# define RUSAGE_CHILDREN 0
#endif

#if defined(EGD_SOCKET) || defined(RANDOM_POOL)

#ifdef EGD_SOCKET
/* Collect entropy from EGD */
int get_random_bytes(unsigned char *buf, int len)
{
	int fd;
	char msg[2];
	struct sockaddr_un addr;
	int addr_len;

	/* Sanity checks */
	if (sizeof(EGD_SOCKET) > sizeof(addr.sun_path))
		fatal("Random pool path is too long");
	if (len > 255)
		fatal("Too many bytes to read from EGD");

	memset(&addr, '\0', sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, EGD_SOCKET, sizeof(addr.sun_path));
	addr_len = offsetof(struct sockaddr_un, sun_path) + sizeof(EGD_SOCKET);
	
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		error("Couldn't create AF_UNIX socket: %s", strerror(errno));
		return(0);
	}

	if (connect(fd, (struct sockaddr*)&addr, addr_len) == -1) {
		error("Couldn't connect to EGD socket \"%s\": %s", 
			addr.sun_path, strerror(errno));
		close(fd);
		return(0);
	}

	/* Send blocking read request to EGD */
	msg[0] = 0x02;
	msg[1] = len;

	if (atomicio(write, fd, msg, sizeof(msg)) != sizeof(msg)) {
		error("Couldn't write to EGD socket \"%s\": %s", 
			EGD_SOCKET, strerror(errno));
		close(fd);
		return(0);
	}

	if (atomicio(read, fd, buf, len) != len) {
		error("Couldn't read from EGD socket \"%s\": %s", 
			EGD_SOCKET, strerror(errno));
		close(fd);
		return(0);
	}
	
	close(fd);
	
	return(1);
}
#else /* !EGD_SOCKET */
#ifdef RANDOM_POOL
/* Collect entropy from /dev/urandom or pipe */
int get_random_bytes(unsigned char *buf, int len)
{
	int random_pool;

	random_pool = open(RANDOM_POOL, O_RDONLY);
	if (random_pool == -1) {
		error("Couldn't open random pool \"%s\": %s", 
			RANDOM_POOL, strerror(errno));
		return(0);
	}
	
	if (atomicio(read, random_pool, buf, len) != len) {
		error("Couldn't read from random pool \"%s\": %s", 
			RANDOM_POOL, strerror(errno));
		close(random_pool);
		return(0);
	}
	
	close(random_pool);
	
	return(1);
}
#endif /* RANDOM_POOL */
#endif /* EGD_SOCKET */

/*
 * Seed OpenSSL's random number pool from Kernel random number generator
 * or EGD
 */
void
seed_rng(void)
{
	char buf[32];
	
	debug("Seeding random number generator");

	if (!get_random_bytes(buf, sizeof(buf))) {
		if (!RAND_status())
			fatal("Entropy collection failed and entropy exhausted");
	} else {
		RAND_add(buf, sizeof(buf), sizeof(buf));
	}
	
	memset(buf, '\0', sizeof(buf));
}

/* No-op */
void init_rng(void) {}

#else /* defined(EGD_SOCKET) || defined(RANDOM_POOL) */

/* 
 * FIXME: proper entropy estimations. All current values are guesses
 * FIXME: (ATL) do estimates at compile time?
 * FIXME: More entropy sources
 */

/* slow command timeouts (all in milliseconds) */
/* static int entropy_timeout_default = ENTROPY_TIMEOUT_MSEC; */
static int entropy_timeout_current = ENTROPY_TIMEOUT_MSEC;

static int prng_seed_saved = 0;
static int prng_initialised = 0;
uid_t original_uid;

typedef struct
{
	/* Proportion of data that is entropy */
	double rate;
	/* Counter goes positive if this command times out */
	unsigned int badness;
	/* Increases by factor of two each timeout */
	unsigned int sticky_badness;
	/* Path to executable */
	char *path;
	/* argv to pass to executable */
	char *args[5];
	/* full command string (debug) */
	char *cmdstring;
} entropy_source_t;

double stir_from_system(void);
double stir_from_programs(void);
double stir_gettimeofday(double entropy_estimate);
double stir_clock(double entropy_estimate);
double stir_rusage(int who, double entropy_estimate);
double hash_output_from_command(entropy_source_t *src, char *hash);

/* this is initialised from a file, by prng_read_commands() */
entropy_source_t *entropy_sources = NULL;

double 
stir_from_system(void)
{
	double total_entropy_estimate;
	long int i;
	
	total_entropy_estimate = 0;
	
	i = getpid();
	RAND_add(&i, sizeof(i), 0.5);
	total_entropy_estimate += 0.1;
	
	i = getppid();
	RAND_add(&i, sizeof(i), 0.5);
	total_entropy_estimate += 0.1;

	i = getuid();
	RAND_add(&i, sizeof(i), 0.0);
	i = getgid();
	RAND_add(&i, sizeof(i), 0.0);

	total_entropy_estimate += stir_gettimeofday(1.0);
	total_entropy_estimate += stir_clock(0.5);
	total_entropy_estimate += stir_rusage(RUSAGE_SELF, 2.0);

	return(total_entropy_estimate);
}

double 
stir_from_programs(void)
{
	int i;
	int c;
	double entropy_estimate;
	double total_entropy_estimate;
	char hash[SHA_DIGEST_LENGTH];

	total_entropy_estimate = 0;
	for(i = 0; i < NUM_ENTROPY_RUNS; i++) {
		c = 0;
		while (entropy_sources[c].path != NULL) {

			if (!entropy_sources[c].badness) {
				/* Hash output from command */
				entropy_estimate = hash_output_from_command(&entropy_sources[c], hash);

				/* Scale back entropy estimate according to command's rate */
				entropy_estimate *= entropy_sources[c].rate;
 
				/* Upper bound of entropy estimate is SHA_DIGEST_LENGTH */
				if (entropy_estimate > SHA_DIGEST_LENGTH)
					entropy_estimate = SHA_DIGEST_LENGTH;

	 			/* Scale back estimates for subsequent passes through list */
				entropy_estimate /= SCALE_PER_RUN * (i + 1.0);
			
				/* Stir it in */
				RAND_add(hash, sizeof(hash), entropy_estimate);

#ifdef DEBUG_ENTROPY
				debug("Got %0.2f bytes of entropy from '%s'", entropy_estimate, 
					entropy_sources[c].cmdstring);
#endif

				total_entropy_estimate += entropy_estimate;

			/* Execution times should be a little unpredictable */
				total_entropy_estimate += stir_gettimeofday(0.05);
				total_entropy_estimate += stir_clock(0.05);
				total_entropy_estimate += stir_rusage(RUSAGE_SELF, 0.1);
				total_entropy_estimate += stir_rusage(RUSAGE_CHILDREN, 0.1);
			} else {
#ifdef DEBUG_ENTROPY
				debug("Command '%s' disabled (badness %d)",
					entropy_sources[c].cmdstring, entropy_sources[c].badness);
#endif

				if (entropy_sources[c].badness > 0)
					entropy_sources[c].badness--;
			}

			c++;
		}
	}
	
	return(total_entropy_estimate);
}

double
stir_gettimeofday(double entropy_estimate)
{
	struct timeval tv;
	
	if (gettimeofday(&tv, NULL) == -1)
		fatal("Couldn't gettimeofday: %s", strerror(errno));

	RAND_add(&tv, sizeof(tv), entropy_estimate);
	
	return(entropy_estimate);
}

double
stir_clock(double entropy_estimate)
{
#ifdef HAVE_CLOCK
	clock_t c;
	
	c = clock();
	RAND_add(&c, sizeof(c), entropy_estimate);
	
	return(entropy_estimate);
#else /* _HAVE_CLOCK */
	return(0);
#endif /* _HAVE_CLOCK */
}

double
stir_rusage(int who, double entropy_estimate)
{
#ifdef HAVE_GETRUSAGE
	struct rusage ru;
	
	if (getrusage(who, &ru) == -1)
		return(0);

	RAND_add(&ru, sizeof(ru), entropy_estimate);

	return(entropy_estimate);
#else /* _HAVE_GETRUSAGE */
	return(0);
#endif /* _HAVE_GETRUSAGE */
}


static
int
_get_timeval_msec_difference(struct timeval *t1, struct timeval *t2) {
	int secdiff, usecdiff;

	secdiff = t2->tv_sec - t1->tv_sec;
	usecdiff = (secdiff*1000000) + (t2->tv_usec - t1->tv_usec);
	return (int)(usecdiff / 1000);
}

double
hash_output_from_command(entropy_source_t *src, char *hash)
{
	static int devnull = -1;
	int p[2];
	fd_set rdset;
	int cmd_eof = 0, error_abort = 0;
	struct timeval tv_start, tv_current;
	int msec_elapsed = 0;
	pid_t pid;
	int status;
	char buf[16384];
	int bytes_read;
	int total_bytes_read;
	SHA_CTX sha;
	
	if (devnull == -1) {
		devnull = open("/dev/null", O_RDWR);
		if (devnull == -1)
			fatal("Couldn't open /dev/null: %s", strerror(errno));
	}
	
	if (pipe(p) == -1)
		fatal("Couldn't open pipe: %s", strerror(errno));

	(void)gettimeofday(&tv_start, NULL); /* record start time */

	switch (pid = fork()) {
		case -1: /* Error */
			close(p[0]);
			close(p[1]);
			fatal("Couldn't fork: %s", strerror(errno));
			/* NOTREACHED */
		case 0: /* Child */
			dup2(devnull, STDIN_FILENO);
			dup2(p[1], STDOUT_FILENO);
			dup2(p[1], STDERR_FILENO);
			close(p[0]);
			close(p[1]);
			close(devnull);

			setuid(original_uid);
			execv(src->path, (char**)(src->args));
			debug("(child) Couldn't exec '%s': %s", src->cmdstring,
			      strerror(errno));
			_exit(-1);
		default: /* Parent */
			break;
	}

	RAND_add(&pid, sizeof(&pid), 0.0);

	close(p[1]);

	/* Hash output from child */
	SHA1_Init(&sha);
	total_bytes_read = 0;

	while (!error_abort && !cmd_eof) {
		int ret;
		struct timeval tv;
		int msec_remaining;

		(void) gettimeofday(&tv_current, 0);
		msec_elapsed = _get_timeval_msec_difference(&tv_start, &tv_current);
		if (msec_elapsed >= entropy_timeout_current) {
			error_abort=1;
			continue;
		}
		msec_remaining = entropy_timeout_current - msec_elapsed;

		FD_ZERO(&rdset);
		FD_SET(p[0], &rdset);
		tv.tv_sec =  msec_remaining / 1000;
		tv.tv_usec = (msec_remaining % 1000) * 1000;

		ret = select(p[0]+1, &rdset, NULL, NULL, &tv);

		RAND_add(&tv, sizeof(tv), 0.0);

		switch (ret) {
		case 0:
			/* timer expired */
			error_abort = 1;
			break;
		case 1:
			/* command input */
			bytes_read = read(p[0], buf, sizeof(buf));
			RAND_add(&bytes_read, sizeof(&bytes_read), 0.0);
			if (bytes_read == -1) {
				error_abort = 1;
				break;
			} else if (bytes_read) {
				SHA1_Update(&sha, buf, bytes_read);
				total_bytes_read += bytes_read;
			} else {
				cmd_eof = 1;
			}
			break;
		case -1:
		default:
			/* error */
			debug("Command '%s': select() failed: %s", src->cmdstring,
			      strerror(errno));
			error_abort = 1;
			break;
		}
	}

	SHA1_Final(hash, &sha);

	close(p[0]);

#ifdef DEBUG_ENTROPY
	debug("Time elapsed: %d msec", msec_elapsed);
#endif
	
	if (waitpid(pid, &status, 0) == -1) {
	       debug("Couldn't wait for child '%s' completion: %s", src->cmdstring,
		     strerror(errno));
		return(0.0);
	}

	RAND_add(&status, sizeof(&status), 0.0);

	if (error_abort) {
		/* closing p[0] on timeout causes the entropy command to
		 * SIGPIPE. Take whatever output we got, and mark this command
		 * as slow */
		debug("Command '%s' timed out", src->cmdstring);
		src->sticky_badness *= 2;
		src->badness = src->sticky_badness;
		return(total_bytes_read);
	}

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status)==0) {
			return(total_bytes_read);
		} else {
			debug("Command '%s' exit status was %d", src->cmdstring, 
				WEXITSTATUS(status));
			src->badness = src->sticky_badness = 128;
			return (0.0);
		}
	} else if (WIFSIGNALED(status)) {
		debug("Command '%s' returned on uncaught signal %d !", src->cmdstring, 
			status);
		src->badness = src->sticky_badness = 128;
		return(0.0);
	} else
		return(0.0);
}

/*
 * prng seedfile functions
 */
int
prng_check_seedfile(char *filename) {

	struct stat st;

	/* FIXME raceable: eg replace seed between this stat and subsequent open */
	/* Not such a problem because we don't trust the seed file anyway */
	if (lstat(filename, &st) == -1) {
		/* Fail on hard errors */
		if (errno != ENOENT)
			fatal("Couldn't stat random seed file \"%s\": %s", filename,
				strerror(errno));

		return(0);
	}

	/* regular file? */
	if (!S_ISREG(st.st_mode))
		fatal("PRNG seedfile %.100s is not a regular file", filename);

	/* mode 0600, owned by root or the current user? */
	if (((st.st_mode & 0177) != 0) || !(st.st_uid == original_uid))
		fatal("PRNG seedfile %.100s must be mode 0600, owned by uid %d",
			 filename, getuid());

	return(1);
}

void
prng_write_seedfile(void) {
	int fd;
	char seed[1024];
	char filename[1024];
	struct passwd *pw;

	/* Don't bother if we have already saved a seed */
	if (prng_seed_saved)
		return;
	
	setuid(original_uid);
	
	prng_seed_saved = 1;
	
	pw = getpwuid(original_uid);
	if (pw == NULL)
		fatal("Couldn't get password entry for current user (%i): %s", 
			original_uid, strerror(errno));
				
	/* Try to ensure that the parent directory is there */
	snprintf(filename, sizeof(filename), "%.512s/%s", pw->pw_dir, 
		SSH_USER_DIR);
	mkdir(filename, 0700);

	snprintf(filename, sizeof(filename), "%.512s/%s", pw->pw_dir, 
		SSH_PRNG_SEED_FILE);

	debug("writing PRNG seed to file %.100s", filename);

	RAND_bytes(seed, sizeof(seed));

	/* Don't care if the seed doesn't exist */
	prng_check_seedfile(filename);
	
	if ((fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1)
		fatal("couldn't access PRNG seedfile %.100s (%.100s)", filename, 
			strerror(errno));
	
	if (atomicio(write, fd, &seed, sizeof(seed)) != sizeof(seed))
		fatal("problem writing PRNG seedfile %.100s (%.100s)", filename, 
			 strerror(errno));

	close(fd);
}

void
prng_read_seedfile(void) {
	int fd;
	char seed[1024];
	char filename[1024];
	struct passwd *pw;
	
	pw = getpwuid(original_uid);
	if (pw == NULL)
		fatal("Couldn't get password entry for current user (%i): %s", 
			original_uid, strerror(errno));
			
	snprintf(filename, sizeof(filename), "%.512s/%s", pw->pw_dir, 
		SSH_PRNG_SEED_FILE);

	debug("loading PRNG seed from file %.100s", filename);

	if (!prng_check_seedfile(filename)) {
		verbose("Random seed file not found, creating new");
		prng_write_seedfile();
		
		/* Reseed immediatly */
		(void)stir_from_system();
		(void)stir_from_programs();
		return;
	}

	/* open the file and read in the seed */
	fd = open(filename, O_RDONLY);
	if (fd == -1)
		fatal("could not open PRNG seedfile %.100s (%.100s)", filename, 
			strerror(errno));

	if (atomicio(read, fd, &seed, sizeof(seed)) != sizeof(seed)) {
		verbose("invalid or short read from PRNG seedfile %.100s - ignoring",
			filename);
		memset(seed, '\0', sizeof(seed));
	}
	close(fd);

	/* stir in the seed, with estimated entropy zero */
	RAND_add(&seed, sizeof(seed), 0.0);
}


/*
 * entropy command initialisation functions
 */
int
prng_read_commands(char *cmdfilename)
{
	FILE *f;
	char *cp;
	char line[1024];
	char cmd[1024];
	char path[256];
	int linenum;
	int num_cmds = 64;
	int cur_cmd = 0;
	double est;
	entropy_source_t *entcmd;

	f = fopen(cmdfilename, "r");
	if (!f) {
		fatal("couldn't read entropy commands file %.100s: %.100s",
		    cmdfilename, strerror(errno));
	}

	entcmd = (entropy_source_t *)xmalloc(num_cmds * sizeof(entropy_source_t));
	memset(entcmd, '\0', num_cmds * sizeof(entropy_source_t));

	/* Read in file */
	linenum = 0;
	while (fgets(line, sizeof(line), f)) {
		int arg;
		char *argv;

		linenum++;

		/* skip leading whitespace, test for blank line or comment */
		cp = line + strspn(line, WHITESPACE);
		if ((*cp == 0) || (*cp == '#'))
			continue; /* done with this line */

		/* First non-whitespace char should be double quote delimiting */
		/* commandline */
		if (*cp != '"') {
			error("bad entropy command, %.100s line %d", cmdfilename,
			     linenum);
			continue;
		}		

		/* first token, command args (incl. argv[0]) in double quotes */
		cp = strtok(cp, "\"");
		if (cp == NULL) {
			error("missing or bad command string, %.100s line %d -- ignored",
			      cmdfilename, linenum);
			continue;
		}
		strlcpy(cmd, cp, sizeof(cmd));
		
		/* second token, full command path */
		if ((cp = strtok(NULL, WHITESPACE)) == NULL) {
			error("missing command path, %.100s line %d -- ignored",
			      cmdfilename, linenum);
			continue;
		}

		/* did configure mark this as dead? */
		if (strncmp("undef", cp, 5) == 0)
			continue;

		strlcpy(path, cp, sizeof(path));			

		/* third token, entropy rate estimate for this command */
		if ((cp = strtok(NULL, WHITESPACE)) == NULL) {
			error("missing entropy estimate, %.100s line %d -- ignored",
			      cmdfilename, linenum);
			continue;
		}
		est = strtod(cp, &argv);

		/* end of line */
		if ((cp = strtok(NULL, WHITESPACE)) != NULL) {
			error("garbage at end of line %d in %.100s -- ignored", linenum, 
				cmdfilename);
			continue;
		}

		/* save the command for debug messages */
		entcmd[cur_cmd].cmdstring = xstrdup(cmd);
			
		/* split the command args */
		cp = strtok(cmd, WHITESPACE);
		arg = 0;
		argv = NULL;
		do {
			char *s = (char*)xmalloc(strlen(cp) + 1);
			strncpy(s, cp, strlen(cp) + 1);
			entcmd[cur_cmd].args[arg] = s;
			arg++;
		} while ((arg < 5) && (cp = strtok(NULL, WHITESPACE)));
		
		if (strtok(NULL, WHITESPACE))
			error("ignored extra command elements (max 5), %.100s line %d",
			      cmdfilename, linenum);

		/* Copy the command path and rate estimate */
		entcmd[cur_cmd].path = xstrdup(path);
		entcmd[cur_cmd].rate = est;

		/* Initialise other values */
		entcmd[cur_cmd].sticky_badness = 1;

		cur_cmd++;

		/* If we've filled the array, reallocate it twice the size */
		/* Do this now because even if this we're on the last command,
		   we need another slot to mark the last entry */
		if (cur_cmd == num_cmds) {
			num_cmds *= 2;
			entcmd = xrealloc(entcmd, num_cmds * sizeof(entropy_source_t));
		}
	}

	/* zero the last entry */
	memset(&entcmd[cur_cmd], '\0', sizeof(entropy_source_t));

	/* trim to size */
	entropy_sources = xrealloc(entcmd, (cur_cmd+1) * sizeof(entropy_source_t));

	debug("Loaded %d entropy commands from %.100s", cur_cmd, cmdfilename);

	return (cur_cmd >= MIN_ENTROPY_SOURCES);
}

/*
 * Write a keyfile at exit
 */ 
void
prng_seed_cleanup(void *junk)
{
	prng_write_seedfile();
}

/*
 * Conditionally Seed OpenSSL's random number pool from
 * syscalls and program output
 */
void
seed_rng(void)
{
	void *old_sigchld_handler;

	if (!prng_initialised)
		fatal("RNG not initialised");
	
	/* Make sure some other sigchld handler doesn't reap our entropy */
	/* commands */
	old_sigchld_handler = signal(SIGCHLD, SIG_DFL);

	debug("Seeded RNG with %i bytes from programs", (int)stir_from_programs());
	debug("Seeded RNG with %i bytes from system calls", (int)stir_from_system());

	if (!RAND_status())
		fatal("Not enough entropy in RNG");

	signal(SIGCHLD, old_sigchld_handler);

	if (!RAND_status())
		fatal("Couldn't initialise builtin random number generator -- exiting.");
}

void init_rng(void) 
{
	original_uid = getuid();

	/* Read in collection commands */
	if (!prng_read_commands(SSH_PRNG_COMMAND_FILE))
		fatal("PRNG initialisation failed -- exiting.");

	/* Set ourselves up to save a seed upon exit */
	prng_seed_saved = 0;		
	prng_read_seedfile();
	fatal_add_cleanup(prng_seed_cleanup, NULL);
	atexit(prng_write_seedfile);

	prng_initialised = 1;
}

#endif /* defined(EGD_SOCKET) || defined(RANDOM_POOL) */
