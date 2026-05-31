// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>

extern "C" {

#include "includes.h"
#include "readconf.h"
#include "log.h"
#include "xmalloc.h"

// Stub out log output to reduce noise
void sshsig_free(struct sshsig_ctx *ctx) {}

}  // extern "C"

static struct passwd fuzz_pw;
static char fuzz_username[] = "fuzzer";
static char fuzz_home[] = "/tmp";
static char fuzz_shell[] = "/bin/sh";

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

    // Write fuzz input to a temp file (read_config_file requires a path)
    char tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0)
        return 0;

    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpfile);
        return 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     &options, 0, NULL);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    return 0;
}
