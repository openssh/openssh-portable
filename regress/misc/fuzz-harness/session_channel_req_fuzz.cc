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
 * Fuzzer for OpenSSH server-side CHANNEL_REQUEST handlers (session.c)
 *
 * Target: session_input_channel_req() and the per-subtype handlers
 *         (session_exec_req, session_subsystem_req, session_env_req,
 *         session_pty_req, session_x11_req, session_window_change_req,
 *         session_signal_req, session_break_req, session_shell_req,
 *         session_auth_agent_req). All are reached via the public
 *         entry point declared in session.h - no source include.
 *
 * Threat model: an authenticated SSH user sends crafted CHANNEL_REQUEST
 * messages to the server. Each per-subtype handler parses its own
 * payload (command strings, env name/value, pty modes, signal name,
 * window dimensions, x11 cookie) before any fork/exec happens. The
 * parse step is the fuzzing target.
 *
 */

#include <stddef.h>
#include <stdint.h>

extern "C" void fuzz_session_one(const uint8_t *data, size_t size);

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz_session_one(data, size);
	return 0;
}
