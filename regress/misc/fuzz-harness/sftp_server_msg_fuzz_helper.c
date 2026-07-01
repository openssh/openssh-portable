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
 * Fuzzer for OpenSSH SFTP server message dispatch (sftp-server.c)
 *
 * Target: sftp-server.c
 *
 * Follows the agent_fuzz_helper.c pattern: #include's sftp-server.c so
 * process() and the static process_* handlers, plus the file-scope
 * globals (iqueue, oqueue, pw, init_done, handles), are reachable from
 * this translation unit. Each iteration bootstraps an FXP_INIT then
 * feeds the fuzzer input as a single framed SFTP message.
 *
 * Primary functions exercised:
 * - process() and the 17 base process_* handlers (open / close / read /
 *   write / stat / lstat / fstat / setstat / fsetstat / opendir /
 *   readdir / remove / mkdir / rmdir / realpath / rename / readlink /
 *   symlink)
 * - process_extended_* (11 variants including posix-rename, statvfs,
 *   hardlink, fsync, lsetstat, limits, expand-path, copy-data,
 *   home-directory, users-groups-by-id)
 * - decode_attrib / encode_attrib (sftp-common.c)
 *
 * Failure handling: fatal() -> cleanup_exit() and
 * sftp_server_cleanup_exit() are intercepted with overriding
 * definitions that longjmp() back to the entry point. fuzz_arena
 * (linker --wrap'd malloc family) frees every still-live allocation on
 * recovery so LSan sees zero per-iteration leaks.
 */

#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

#include "log.h"

extern void fuzz_arena_begin(void);
extern void fuzz_arena_release(void);
extern void fuzz_arena_cleanup(void);

static jmp_buf fuzz_server_env;
static volatile int in_fuzz_server = 0;

void
cleanup_exit(int code)
{
	if (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

#define sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#include "../../../sftp-server.c"
#undef sftp_server_cleanup_exit

void
sftp_server_cleanup_exit(int code)
{
	if (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

static void (* const __force_use_renamed)(int) =
    __orig_sftp_server_cleanup_exit;

static struct passwd fuzz_pw;
static int log_initialized = 0;

static void
cleanup_handles(void)
{
	u_int i;
	if (handles == NULL)
		return;
	for (i = 0; i < num_handles; i++) {
		if (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		else if (handles[i].use == HANDLE_DIR && handles[i].dirp != NULL)
			closedir(handles[i].dirp);
		free(handles[i].name);
	}
	free(handles);
	handles = NULL;
	num_handles = 0;
	first_unused_handle = -1;
}

static void
reset_module_globals(void)
{
	pw = &fuzz_pw;
	client_addr = NULL;
	version = 0;
	init_done = 0;
	readonly = 0;
	request_allowlist = NULL;
	request_denylist = NULL;
	handles = NULL;
	num_handles = 0;
	first_unused_handle = -1;
	iqueue = NULL;
	oqueue = NULL;
}

void
fuzz_server_one(const uint8_t *data, size_t size)
{
	if (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		char tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		if (mkdtemp(tmpdir) != NULL && chdir(tmpdir) != 0)
			_exit(1);

		memset(&fuzz_pw, 0, sizeof(fuzz_pw));
		fuzz_pw.pw_name = (char *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (char *)"/tmp";
		fuzz_pw.pw_shell = (char *)"/bin/sh";
	}

	if (size == 0 || size > 65000)
		return;

	reset_module_globals();

	fuzz_arena_begin();
	in_fuzz_server = 1;
	if (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		if (iqueue == NULL || oqueue == NULL)
			goto out;

		const uint8_t init_msg[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		if (sshbuf_put(iqueue, init_msg, sizeof(init_msg)) != 0)
			goto out;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((size >> 24) & 0xff),
		    (uint8_t)((size >> 16) & 0xff),
		    (uint8_t)((size >> 8) & 0xff),
		    (uint8_t)(size & 0xff),
		};
		if (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, data, size) != 0)
			goto out;
		process();
	out:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		free(client_addr);
		iqueue = oqueue = NULL;
		client_addr = NULL;
		in_fuzz_server = 0;
		fuzz_arena_release();
		return;
	}
	cleanup_handles();
	in_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = NULL;
	client_addr = NULL;
}
