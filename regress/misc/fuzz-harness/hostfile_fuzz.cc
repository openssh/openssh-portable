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

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {

#include "hostfile.h"
#include "sshkey.h"
#include "log.h"

static int log_initialized = 0;

static int
noop_cb(struct hostkey_foreach_line *l, void *ctx)
{
	(void)l; (void)ctx;
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	static const u_int flag_combos[] = {
		0,
		HKF_WANT_MATCH,
		HKF_WANT_PARSE_KEY,
		HKF_WANT_MATCH | HKF_WANT_PARSE_KEY,
	};
	for (size_t i = 0; i < sizeof(flag_combos)/sizeof(flag_combos[0]); i++) {
		FILE *f = fmemopen((void *)data, size, "r");
		if (f == NULL)
			continue;
		const char *host = (flag_combos[i] & HKF_WANT_MATCH) ?
		    "example.com" : NULL;
		(void)hostkeys_foreach_file("/fuzz", f, noop_cb, NULL,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((void *)data, size, "r");
		if (f != NULL) {
			struct hostkeys *hk = init_hostkeys();
			if (hk != NULL) {
				load_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	if (size > 0) {
		size_t n = size < 256 ? size : 256;
		char *hb = (char *)malloc(n + 1);
		if (hb != NULL) {
			memcpy(hb, data, n);
			hb[n] = '\0';
			char *h = host_hash("example.com", hb, 0);
			free(h);
			free(hb);
		}
	}

	return 0;
}

} // extern "C"
