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

#ifdef HAVE_OPENSSL
# include <openssl/rand.h>
# include <openssl/sha.h>
#endif
#ifdef HAVE_SSL
# include <ssl/rand.h>
# include <ssl/sha.h>
#endif

RCSID("$Id: entropy.c,v 1.2 2000/04/03 05:07:32 damien Exp $");

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
 * FIXME: Need timeout for slow moving programs
 * FIXME: More entropy sources
 */

double stir_from_system(void);
double stir_from_programs(void);
double stir_gettimeofday(double entropy_estimate);
double stir_clock(double entropy_estimate);
double stir_rusage(int who, double entropy_estimate);
double hash_output_from_command(const char *path, const char **args, char *hash);

typedef struct
{
	/* Proportion of data that is entropy */
	double rate;
	/* Path to executable */
	const char *path;
	/* argv to pass to executable */
	const char *args[5];
} entropy_source_t;

entropy_source_t entropy_sources[] = {
#ifdef PROG_LS
	{ 0.002, PROG_LS,       { "ls", "-alni", "/var/log", NULL } },
	{ 0.002, PROG_LS,       { "ls", "-alni", "/var/adm", NULL } },
	{ 0.002, PROG_LS,       { "ls", "-alni", "/var/mail", NULL } },
	{ 0.002, PROG_LS,       { "ls", "-alni", "/var/spool/mail", NULL } },
	{ 0.002, PROG_LS,       { "ls", "-alni", "/proc", NULL } },
	{ 0.002, PROG_LS,       { "ls", "-alni", "/tmp", NULL } },
#endif
#ifdef PROG_NETSTAT
	{ 0.005, PROG_NETSTAT,  { "netstat","-an", NULL, NULL } },
	{ 0.010, PROG_NETSTAT,  { "netstat","-in", NULL, NULL } },
	{ 0.002, PROG_NETSTAT,  { "netstat","-rn", NULL, NULL } },
	{ 0.002, PROG_NETSTAT,  { "netstat","-s", NULL, NULL } },
#endif
#ifdef PROG_ARP
	{ 0.002, PROG_ARP,      { "arp","-a","-n", NULL } },
#endif
#ifdef PROG_IFCONFIG
	{ 0.002, PROG_IFCONFIG, { "ifconfig", "-a", NULL, NULL } },
#endif
#ifdef PROG_PS
	{ 0.003, PROG_PS,       { "ps", "laxww", NULL, NULL } },
	{ 0.003, PROG_PS,       { "ps", "-al", NULL, NULL } },
	{ 0.003, PROG_PS,       { "ps", "-efl", NULL, NULL } },
#endif
#ifdef PROG_W
	{ 0.005, PROG_W,        { "w", NULL, NULL, NULL } },
#endif
#ifdef PROG_WHO
	{ 0.001, PROG_WHO,      { "who","-i", NULL, NULL } },
#endif
#ifdef PROG_LAST
	{ 0.001, PROG_LAST,     { "last", NULL, NULL, NULL } },
#endif
#ifdef PROG_LASTLOG
	{ 0.001, PROG_LASTLOG,  { "lastlog", NULL, NULL, NULL } },
#endif
#ifdef PROG_DF
	{ 0.010, PROG_DF,       { "df", NULL, NULL, NULL } },
	{ 0.010, PROG_DF,       { "df", "-i", NULL, NULL } },
#endif
#ifdef PROG_VMSTAT
	{ 0.010, PROG_VMSTAT,   { "vmstat", NULL, NULL, NULL } },
#endif
#ifdef PROG_UPTIME
	{ 0.001, PROG_UPTIME,   { "uptime", NULL, NULL, NULL } },
#endif
#ifdef PROG_IPCS
	{ 0.001, PROG_IPCS,     { "-a", NULL, NULL, NULL } },
#endif
#ifdef PROG_TAIL
	{ 0.001, PROG_TAIL,     { "tail", "-200", "/var/log/messages", NULL, NULL } },
	{ 0.001, PROG_TAIL,     { "tail", "-200", "/var/log/syslog", NULL, NULL } },
	{ 0.001, PROG_TAIL,     { "tail", "-200", "/var/adm/messages", NULL, NULL } },
	{ 0.001, PROG_TAIL,     { "tail", "-200", "/var/adm/syslog", NULL, NULL } },
	{ 0.001, PROG_TAIL,     { "tail", "-200", "/var/log/maillog", NULL, NULL } },
	{ 0.001, PROG_TAIL,     { "tail", "-200", "/var/adm/maillog", NULL, NULL } },
#endif
	{ 0.000, NULL,          { NULL, NULL, NULL, NULL, NULL } },
};


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
			/* Hash output from command */
			entropy_estimate = hash_output_from_command(entropy_sources[c].path,
				entropy_sources[c].args, hash);

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
hash_output_from_command(const char *path, const char **args, char *hash)
{
	static int devnull = -1;
	int p[2];
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
			close(0);
			close(1);
			close(2);
			dup2(devnull, 0);
			dup2(p[1], 1);
			dup2(p[1], 2);
			close(p[0]);
			close(p[1]);
			close(devnull);

			execv(path, (char**)args);
			debug("(child) Couldn't exec '%s': %s", path, strerror(errno));
			_exit(-1);
		default: /* Parent */
			break;
	}

	RAND_add(&pid, sizeof(&pid), 0.0);

	close(p[1]);

	/* Hash output from child */
	SHA1_Init(&sha);
	total_bytes_read = 0;
	while ((bytes_read = read(p[0], buf, sizeof(buf)))	> 0) {
		SHA1_Update(&sha, buf, bytes_read);
		total_bytes_read += bytes_read;
		RAND_add(&bytes_read, sizeof(&bytes_read), 0.0);
	}
	SHA1_Final(hash, &sha);

	close(p[0]);
	
	if (waitpid(pid, &status, 0) == -1) {
		error("Couldn't wait for child '%s' completion: %s", path, 
			strerror(errno));
		return(-1);
	}

	RAND_add(&status, sizeof(&status), 0.0);

	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0))
		return(0.0);
	else
		return(total_bytes_read);
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
 * Conditionally Seed OpenSSL's random number pool syscalls and program output
 */
void
seed_rng(void)
{
	if (!RAND_status()) {
		debug("Seeding random number generator.");
		debug("%i bytes from system calls", (int)stir_from_system());
		debug("%i bytes from programs", (int)stir_from_programs());
		debug("OpenSSL random status is now %i\n", RAND_status());
	}
}
#endif /* defined(EGD_SOCKET) || defined(RANDOM_POOL) */
