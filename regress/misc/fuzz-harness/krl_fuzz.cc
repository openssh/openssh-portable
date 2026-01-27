// libfuzzer driver for krl parse fuzzing.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern "C" {
#include "includes.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "krl.h"
#include "log.h"
#include "authfile.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Slient logs
    log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

    // Reject empty corpus
    if (size < 4) return 0;

    // Convert fuzzer data to ssh buffer
    struct sshbuf *buf = sshbuf_from(data, size);
    if (!buf) return 0;

    // Parse the ssh buffer as krl, early exit if failed
    struct ssh_krl *krl = NULL;
    int ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    if (ret != 0) return 0;

    // Fuzz serailisation roundtrip
    struct sshbuf *output = sshbuf_new();
    struct ssh_krl *krl2 = NULL;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    FILE *null_file = fopen("/dev/null", "w");
    krl_dump(krl, null_file);
    fclose(null_file);

    // Fuzz ssh_krl_check_key
    struct sshkey *key = NULL;
    sshkey_generate(KEY_RSA, 2048, &key);
    ssh_krl_check_key(krl, key);
    sshkey_free(key);

    ssh_krl_free(krl);
    return 0;
}
