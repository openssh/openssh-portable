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

RCSID("$Id: entropy.c,v 1.8 2000/05/01 23:56:41 damien Exp $");

#ifdef EGD_SOCKET
#ifndef offsetof
# define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif
/* Collect entropy from EGD */
void get_random_bytes(unsigned char *buf, int len)
{
	static int egd_socket = -1;
	int c;
	char egd_message[2] = { 0x02, 0x00 };
	struct sockaddr_un addr;
	int addr_len;

	memset(&addr, '\0', sizeof(addr));
	addr.sun_family = AF_UNIX;
	
	/* FIXME: compile time check? */
	if (sizeof(EGD_SOCKET) > sizeof(addr.sun_path))
		fatal("Random pool path is too long");
	
	strcpy(addr.sun_path, EGD_SOCKET);
	
	addr_len = offsetof(struct sockaddr_un, sun_path) + sizeof(EGD_SOCKET);
	
	if (egd_socket == -1) {
		egd_socket = socket(AF_UNIX, SOCK_STREAM, 0);
		if (egd_socket == -1)
			fatal("Couldn't create AF_UNIX socket: %s", strerror(errno));
		if (connect(egd_socket, (struct sockaddr*)&addr, addr_len) == -1)
			fatal("Couldn't connect to EGD socket \"%s\": %s", addr.sun_path, strerror(errno));
	}	

	if (len > 255)
		fatal("Too many bytes to read from EGD");
	
	/* Send blocking read request to EGD */
	egd_message[1] = len;

	c = atomicio(write, egd_socket, egd_message, sizeof(egd_message));
	if (c == -1)
		fatal("Couldn't write to EGD socket \"%s\": %s", EGD_SOCKET, strerror(errno));

	c = atomicio(read, egd_socket, buf, len);
	if (c <= 0)
		fatal("Couldn't read from EGD socket \"%s\": %s", EGD_SOCKET, strerror(errno));
	
	close(EGD_SOCKET);
}
#else /* !EGD_SOCKET */
#ifdef RANDOM_POOL
/* Collect entropy from /dev/urandom or pipe */
void get_random_bytes(unsigned char *buf, int len)
{
	static int random_pool = -1;
	int c;

	if (random_pool == -1) {
		random_pool = open(RANDOM_POOL, O_RDONLY);
		if (random_pool == -1)
			fatal("Couldn't open random pool \"%s\": %s", RANDOM_POOL, strerror(errno));
	}
	
	c = atomicio(read, random_pool, buf, len);
	if (c <= 0)
		fatal("Couldn't read from random pool \"%s\": %s", RANDOM_POOL, strerror(errno));
}
#endif /* RANDOM_POOL */
#endif /* EGD_SOCKET */

#if !defined(EGD_SOCKET) && !defined(RANDOM_POOL)
/* 
 * FIXME: proper entropy estimations. All current values are guesses
 * FIXME: (ATL) do estimates at compile time?
 * FIXME: More entropy sources
 */

/* slow command timeouts (all in milliseconds) */
/* static int entropy_timeout_default = ENTROPY_TIMEOUT_MSEC; */
static int entropy_timeout_current = ENTROPY_TIMEOUT_MSEC;

static int prng_seed_loaded = 0;
static int prng_seed_saved = 0;
static int prng_commands_loaded = 0;

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
} entropy_source_t;

double stir_from_system(void);
double stir_from_programs(void);
double stir_gettimeofday(double entropy_estimate);
double stir_clock(double entropy_estimate);
double stir_rusage(int who, double entropy_estimate);
double hash_output_from_command(entropy_source_t *src, char *hash);

/* this is initialised from a file, by prng_read_commands() */
entropy_source_t *entropy_sources = NULL;
#define MIN_ENTROPY_SOURCES 16


double 
stir_from_system(void)
{
	double total_entropy_estimate;
	long int i;
	
	total_entropy_estimate = 0;
	
	i = getpid();
	RAND_add(&i, sizeof(i), 0.1);
	total_entropy_estimate += 0.1;
	
	i = getppid();
	RAND_add(&i, sizeof(i), 0.1);
	total_entropy_estimate += 0.1;

	i = getuid();
	RAND_add(&i, sizeof(i), 0.0);
	i = getgid();
	RAND_add(&i, sizeof(i), 0.0);

	total_entropy_estimate += stir_gettimeofday(1.0);
	total_entropy_estimate += stir_clock(0.2);
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

	/*
	 * Run through list of programs twice to catch differences
	 */
	total_entropy_estimate = 0;
	for(i = 0; i < 2; i++) {
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

 			/* * Scale back estimates for subsequent passes through list */
				entropy_estimate /= 10.0 * (i + 1.0);
			
				/* Stir it in */
				RAND_add(hash, sizeof(hash), entropy_estimate);

/* FIXME: turn this off later */
#if 1
				debug("Got %0.2f bytes of entropy from %s", entropy_estimate, 
					entropy_sources[c].path);
#endif

				total_entropy_estimate += entropy_estimate;

			/* Execution times should be a little unpredictable */
				total_entropy_estimate += stir_gettimeofday(0.05);
				total_entropy_estimate += stir_clock(0.05);
				total_entropy_estimate += stir_rusage(RUSAGE_SELF, 0.1);
				total_entropy_estimate += stir_rusage(RUSAGE_CHILDREN, 0.1);
			} else {
/* FIXME: turn this off later */
#if 1
				debug("Command '%s %s %s' disabled (badness %d)",
					entropy_sources[c].path, entropy_sources[c].args[1],
					entropy_sources[c].args[2], entropy_sources[c].badness);
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
		fatal("Couldn't getrusage: %s", strerror(errno));

	RAND_add(&ru, sizeof(ru), 0.1);

	return(entropy_estimate);
#else /* _HAVE_GETRUSAGE */
	return(0);
#endif /* _HAVE_GETRUSAGE */
}

double
hash_output_from_command(entropy_source_t *src, char *hash)
{
	static int devnull = -1;
	int p[2];
	fd_set rdset;
	int cmd_eof = 0, error_abort = 0;
	pid_t pid;
	int status;
	char buf[2048];
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

			execv(src->path, (char**)(src->args));
			debug("(child) Couldn't exec '%s %s %s': %s", src->path,
				src->args[1], src->args[2], strerror(errno));
			src->badness = src->sticky_badness = 128;
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

		FD_ZERO(&rdset);
		FD_SET(p[0], &rdset);
		tv.tv_sec = entropy_timeout_current / 1000;
		tv.tv_usec = (entropy_timeout_current % 1000) * 1000;

		ret = select(p[0]+1, &rdset, NULL, NULL, &tv);
		switch (ret) {
		case 0:
			/* timer expired */
			error_abort = 1;
			break;
			
		case 1:
			/* command input */
			bytes_read = read(p[0], buf, sizeof(buf));
			if (bytes_read == -1) {
				error_abort = 1;
				break;
			}
			SHA1_Update(&sha, buf, bytes_read);
			total_bytes_read += bytes_read;
			RAND_add(&bytes_read, sizeof(&bytes_read), 0.0);
			cmd_eof = bytes_read ? 0 : 1;

			break;

		case -1:
		default:
			error("Command '%s %s': select() failed: %s", src->path, src->args[1],
				strerror(errno));
			error_abort = 1;
			break;
		} /* switch ret */

		RAND_add(&tv, sizeof(&tv), 0.0);
	} /* while !error_abort && !cmd_eof */

	SHA1_Final(hash, &sha);

	close(p[0]);
	
	if (waitpid(pid, &status, 0) == -1) {
		error("Couldn't wait for child '%s %s' completion: %s", src->path,
			src->args[1], strerror(errno));
		/* return(-1); */ /* FIXME: (ATL) this doesn't feel right */
		return(0.0);
	}

	RAND_add(&status, sizeof(&status), 0.0);

	if (error_abort) {
		/* closing p[0] on timeout causes the entropy command to
		 * SIGPIPE. Take whatever output we got, and mark this command
		 * as slow */
		debug("Command %s %s timed out", src->path, src->args[1]);
		src->sticky_badness *= 2;
		src->badness = src->sticky_badness;
		return(total_bytes_read);
	}

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status)==0) {
			return(total_bytes_read);
		} else {
			debug("Exit status was %d", WEXITSTATUS(status));
			src->badness = src->sticky_badness = 128;
			return (0.0);
		}
	} else if (WIFSIGNALED(status)) {
		debug("Returned on uncaught signal %d !", status);
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
	if (((st.st_mode & 0177) != 0) || !(st.st_uid == geteuid()))
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
	
	prng_seed_saved = 1;
	
	pw = getpwuid(getuid());
	if (pw == NULL)
		fatal("Couldn't get password entry for current user (%i): %s", 
			getuid(), strerror(errno));
				
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
	
	pw = getpwuid(getuid());
	if (pw == NULL)
		fatal("Couldn't get password entry for current user (%i): %s", 
			getuid(), strerror(errno));
			
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
#define WHITESPACE " \t\n"

int
prng_read_commands(char *cmdfilename)
{
	FILE *f;
	char line[1024];
	char cmd[1024], path[256];
	double est;
	char *cp;
	int linenum;
	entropy_source_t *entcmd;
	int num_cmds = 64;
	int cur_cmd = 0;

	f = fopen(cmdfilename, "r");
	if (!f) {
		fatal("couldn't read entropy commands file %.100s: %.100s",
		    cmdfilename, strerror(errno));
	}

	linenum = 0;

	entcmd = (entropy_source_t *)xmalloc(num_cmds * sizeof(entropy_source_t));
	memset(entcmd, '\0', num_cmds * sizeof(entropy_source_t));

	while (fgets(line, sizeof(line), f)) {
		linenum++;

		/* skip leading whitespace, test for blank line or comment */
		cp = line + strspn(line, WHITESPACE);
		if ((*cp == 0) || (*cp == '#'))
			continue; /* done with this line */

		switch (*cp) {
			int arg;
			char *argv;

		case '"':
			/* first token, command args (incl. argv[0]) in double quotes */
			cp = strtok(cp, "\"");
			if (cp==NULL) {
				error("missing or bad command string, %.100s line %d -- ignored",
				      cmdfilename, linenum);
				continue;
			}
			strncpy(cmd, cp, sizeof(cmd));
			/* second token, full command path */
			if ((cp = strtok(NULL, WHITESPACE)) == NULL) {
				error("missing command path, %.100s line %d -- ignored",
				      cmdfilename, linenum);
				continue;
			}
			if (strncmp("undef", cp, 5)==0)   /* did configure mark this as dead? */
				continue;

			strncpy(path, cp, sizeof(path));			
			/* third token, entropy rate estimate for this command */
			if ( (cp = strtok(NULL, WHITESPACE)) == NULL) {
				error("missing entropy estimate, %.100s line %d -- ignored",
				      cmdfilename, linenum);
				continue;
			}
			est = strtod(cp, &argv);/* FIXME: (ATL) no error checking here */

			/* end of line */
			if ((cp = strtok(NULL, WHITESPACE)) != NULL) {
				error("garbage at end of line %d in %.100s -- ignored",
				      linenum, cmdfilename);
				continue;
			}

			/* split the command args */
			cp = strtok(cmd, WHITESPACE);
			arg = 0; argv = NULL;
			do {
				char *s = (char*)xmalloc(strlen(cp)+1);
				strncpy(s, cp, strlen(cp)+1);
				entcmd[cur_cmd].args[arg] = s;
				arg++;
			} while ((arg < 5) && (cp = strtok(NULL, WHITESPACE)));
			if (strtok(NULL, WHITESPACE))
				error("ignored extra command elements (max 5), %.100s line %d",
				      cmdfilename, linenum);

			/* copy the command path and rate estimate */
			entcmd[cur_cmd].path = (char *)xmalloc(strlen(path)+1);
			strncpy(entcmd[cur_cmd].path, path, strlen(path)+1);
		        entcmd[cur_cmd].rate = est;
			/* initialise other values */
			entcmd[cur_cmd].sticky_badness = 1;

			cur_cmd++;

			/* If we've filled the array, reallocate it twice the size */
			/* Do this now because even if this we're on the last command,
			   we need another slot to mark the last entry */
			if (cur_cmd == num_cmds) {
				num_cmds *= 2;
				entcmd = xrealloc(entcmd, num_cmds * sizeof(entropy_source_t));
			}
			break;

		default:
			error("bad entropy command, %.100s line %d", cmdfilename,
			     linenum);
			continue;
		}
	}

	/* zero the last entry */
	memset(&entcmd[cur_cmd], '\0', sizeof(entropy_source_t));
	/* trim to size */
	entropy_sources = xrealloc(entcmd, (cur_cmd+1) * sizeof(entropy_source_t));

	debug("loaded %d entropy commands from %.100s", cur_cmd, cmdfilename);

	return (cur_cmd >= MIN_ENTROPY_SOURCES);
}


#endif /* defined(EGD_SOCKET) || defined(RANDOM_POOL) */

#if defined(EGD_SOCKET) || defined(RANDOM_POOL)

/*
 * Seed OpenSSL's random number pool from Kernel random number generator
 * or EGD
 */
void
seed_rng(void)
{
	char buf[32];
	
	debug("Seeding random number generator");
	get_random_bytes(buf, sizeof(buf));
	RAND_add(buf, sizeof(buf), sizeof(buf));
	memset(buf, '\0', sizeof(buf));
}

#else /* defined(EGD_SOCKET) || defined(RANDOM_POOL) */

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
	if (!prng_commands_loaded) {
		if (!prng_read_commands(SSH_PRNG_COMMAND_FILE))
			fatal("PRNG initialisation failed -- exiting.");
		prng_commands_loaded = 1;
	}

	debug("Seeding random number generator.");
	debug("OpenSSL random status is now %i\n", RAND_status());
	debug("%i bytes from system calls", (int)stir_from_system());
	debug("%i bytes from programs", (int)stir_from_programs());
	debug("OpenSSL random status is now %i\n", RAND_status());

	if (!prng_seed_loaded)
	{
		prng_seed_loaded = 1;
		prng_seed_saved = 0;		
		prng_read_seedfile();
		fatal_add_cleanup(prng_seed_cleanup, NULL);
		atexit(prng_write_seedfile);
	}
}
#endif /* defined(EGD_SOCKET) || defined(RANDOM_POOL) */
