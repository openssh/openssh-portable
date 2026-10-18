// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#include <sys/types.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>

extern "C" {

#include "includes.h"
#include "ssh.h"
#include "misc.h"
#include "log.h"
#include "readconf.h"
#include "xmalloc.h"

// Stub out log output to reduce noise
void sshsig_free(struct sshsig_ctx *ctx) {}

}  // extern "C"

static struct passwd fuzz_pw;
static char fuzz_username[] = "fuzzer";
static char fuzz_home[] = "/tmp";
static char fuzz_shell[] = "/bin/sh";
static jmp_buf fuzz_env;
static volatile int in_fuzz = 0;

extern "C" void
cleanup_exit(int code)
{
    if (in_fuzz)
        longjmp(fuzz_env, code ? code : 1);
    _exit(code);
}

static void init_pw(void) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int initialized = 0;
    if (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    Options options;
    char *line;
    int active = 1;
    int r;

    initialize_options(&options);
    line = static_cast<char *>(xmalloc(size + 1));
    memcpy(line, data, size);
    line[size] = '\0';

    // Invalid configuration may return an error or call fatal().
    in_fuzz = 1;
    if (setjmp(fuzz_env) == 0) {
        r = process_config_line(&options, &fuzz_pw, "fuzz.example.com",
                                "fuzz.example.com", NULL, line, "<fuzz>", 1,
                                &active, 0);
    } else {
        r = -1;
    }
    in_fuzz = 0;

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    free(line);
    return r == 0 ? 0 : -1;
}
