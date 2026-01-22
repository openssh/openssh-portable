// libfuzzer driver for krl parse fuzzing.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern "C" {
#include "includes.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "krl.h"
#include "log.h"
#include "authfile.h"
}

static int initialized = 0;

static void setup() {
    if (initialized) return;
    initialized = 1;

    // Slient the logging
    log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    setup();

    // Reject empty or overly large inputs
    if (size < 4 || size > 100000) {
        return 0;
    }

    // Convert fuzzer data to ssh buffer
    struct sshbuf *buf = sshbuf_from(data, size);
    if (!buf) return 0;

    // Parse the ssh buffer as krl
    struct ssh_krl *krl = NULL;
    int ret = ssh_krl_from_blob(buf, &krl);

    if (ret == 0 && krl != NULL) {
        // Fuzz round trip KRL parsing
        struct sshbuf *output = sshbuf_new();
        if (output) {
            ret = ssh_krl_to_blob(krl, output);
            if (ret == 0) {
                struct ssh_krl *krl2 = NULL;
                ret = ssh_krl_from_blob(output, &krl2);
                if (ret == 0 && krl2) {
                    ssh_krl_free(krl2);
                }
            }
            sshbuf_free(output);
        }

        ssh_krl_free(krl);
    }

    sshbuf_free(buf);
    return 0;
}
