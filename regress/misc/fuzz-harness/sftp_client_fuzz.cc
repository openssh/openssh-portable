/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for OpenSSH SFTP client response parser (sftp-client.c)
 *
 * Target: sftp-client.c
 *
 * Drives every public sftp-client API on a socketpair using the
 * fuzzer input as the reply payload. A helper opens a fresh
 * socketpair, pre-fills a valid FXP_VERSION reply so sftp_init
 * succeeds, then writes the fuzzer body which the API call consumes
 * as its own response. Each iteration runs all 12 APIs on the same
 * input so no API is starved by a selector byte.
 *
 * Primary functions exercised:
 * - sftp_init, sftp_stat, sftp_lstat, sftp_realpath, sftp_expand_path
 * - sftp_readdir, sftp_statvfs, sftp_get_limits
 * - sftp_rm, sftp_mkdir, sftp_rmdir, sftp_rename, sftp_symlink
 * - decode_attrib via every reply path (sftp-common.c)
 *
 * Threat model: a malicious SFTP server returning crafted attribute
 * lists, name lists, status responses, and statvfs payloads to a
 * connected client (sshfs, sftp, scp to a hostile host).
 *
 * Failure handling: sftp-client.c calls fatal() liberally on
 * protocol violations. A custom cleanup_exit() longjmp()s back to
 * the helper. fuzz_arena (linker --wrap'd malloc family) frees
 * every still-live allocation on both the success and longjmp paths
 * so LSan sees zero per-iteration leaks.
 */

#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

extern "C" {
#include "includes.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"

void fuzz_arena_begin(void);
void fuzz_arena_cleanup(void);
}

extern "C" volatile sig_atomic_t interrupted = 0;
extern "C" int showprogress = 0;
extern "C" void start_progress_meter(const char *file, off_t filesize,
    off_t *ctr) { (void)file; (void)filesize; (void)ctr; }
extern "C" void refresh_progress_meter(int force_update) { (void)force_update; }
extern "C" void stop_progress_meter(void) { }

static jmp_buf fuzz_env;
static volatile int in_fuzz = 0;

extern "C" void
cleanup_exit(int code)
{
	if (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

static const uint8_t k_version_reply[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

enum {
	API_STAT,
	API_LSTAT,
	API_REALPATH,
	API_EXPAND_PATH,
	API_READDIR,
	API_STATVFS,
	API_GET_LIMITS,
	API_RM,
	API_MKDIR,
	API_RMDIR,
	API_RENAME,
	API_SYMLINK,
	API_COUNT,
};

static void
run_one(int api, const uint8_t *body, size_t bsize)
{
	int sv[2] = { -1, -1 };
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return;

	ssize_t w = write(sv[0], k_version_reply, sizeof(k_version_reply));
	(void)w;
	if (bsize > 0)
		w = write(sv[0], body, bsize);
	(void)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	in_fuzz = 1;
	if (setjmp(fuzz_env) == 0) {
		struct sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		if (conn != NULL) {
			Attrib attr;
			attrib_clear(&attr);

			switch (api) {
			case API_STAT: {
				Attrib a;
				(void)sftp_stat(conn, "/fuzz", 1, &a);
				break;
			}
			case API_LSTAT: {
				Attrib a;
				(void)sftp_lstat(conn, "/fuzz", 1, &a);
				break;
			}
			case API_REALPATH: {
				char *p = sftp_realpath(conn, "/fuzz");
				free(p);
				break;
			}
			case API_EXPAND_PATH: {
				char *p = sftp_expand_path(conn, "~");
				free(p);
				break;
			}
			case API_READDIR: {
				SFTP_DIRENT **dir = NULL;
				(void)sftp_readdir(conn, "/fuzz", &dir);
				if (dir != NULL)
					sftp_free_dirents(dir);
				break;
			}
			case API_STATVFS: {
				struct sftp_statvfs vfs;
				(void)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				break;
			}
			case API_GET_LIMITS: {
				struct sftp_limits lim;
				(void)sftp_get_limits(conn, &lim);
				break;
			}
			case API_RM:
				(void)sftp_rm(conn, "/fuzz");
				break;
			case API_MKDIR:
				(void)sftp_mkdir(conn, "/fuzz", &attr, 0);
				break;
			case API_RMDIR:
				(void)sftp_rmdir(conn, "/fuzz");
				break;
			case API_RENAME:
				(void)sftp_rename(conn, "/a", "/b", 0);
				break;
			case API_SYMLINK:
				(void)sftp_symlink(conn, "/a", "/b");
				break;
			}

			sftp_free(conn);
		}
	}
	in_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int initialized = 0;
	if (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	if (size > 65536)
		return 0;

	for (int api = 0; api < API_COUNT; api++)
		run_one(api, data, size);

	return 0;
}
