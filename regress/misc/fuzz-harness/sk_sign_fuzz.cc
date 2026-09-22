/*
 * libFuzzer harness for sk_sign() (sk-usbhid.c), the FIDO2/U2F
 * GetAssertion path exercised by sshd/ssh-sk-helper during interactive
 * "sk-ecdsa-sha2-nistp256@openssh.com" / "sk-ssh-ed25519@openssh.com"
 * public key authentication.
 *
 * This links the *real* sk-usbhid.c against libfido2/libcbor. To avoid
 * touching real USB hardware, sk-usbhid.c is compiled with
 * -Dfido_dev_new=fuzz_fido_dev_new (see Makefile), so its single
 * fido_dev_new() call resolves to fuzz_fido_dev_new() below, which
 * installs a fake fido_dev_io_t that serves bytes out of wire_buf.
 *
 * wire_buf is a fixed CTAPHID_INIT + authenticatorGetInfo prefix (lifted
 * from libfido2/fuzz/wiredata_fido2.h, see sk_sign_wiredata.h) so that
 * fido_dev_open() succeeds and the device is recognised as CTAP2,
 * followed by the fuzzer-controlled bytes. Those fuzzer bytes are what
 * fido_dev_get_assert() reads back as the authenticatorGetAssertion
 * response -- i.e. attacker-controlled CTAP2/CBOR data from a malicious
 * or compromised security key.
 *
 * This is the same fake-transport technique as open_dev()/set_wire_data()
 * in libfido2/fuzz/fuzz_assert.c.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
#include <fido.h>
#include "../../../sk-api.h"

/*
 * Provided by libfido2 when built with its fuzzing instrumentation
 * (see libfido2/fuzz/prng.c and fuzz/clock.c): replaces getentropy(2)
 * and clock_gettime(2) with deterministic, seedable equivalents.
 * fido_dev_open()'s CTAPHID_INIT nonce generation calls uniform_random(),
 * which asserts that prng_init() has been called first.
 */
void prng_init(unsigned long seed);
void fuzz_clock_reset(void);
}

#include "sk_sign_wiredata.h"

namespace {

const uint8_t kPrefix[] = { WIREDATA_CTAP_INIT, WIREDATA_CTAP_CBOR_INFO };

constexpr size_t kMaxFuzz = 16384;

uint8_t wire_buf[sizeof(kPrefix) + kMaxFuzz];
const uint8_t *wire_ptr;
size_t wire_len;

extern "C" void *
fuzz_hid_open(const char *path)
{
	(void)path;

	return wire_buf; /* any non-NULL opaque handle */
}

extern "C" void
fuzz_hid_close(void *handle)
{
	(void)handle;
}

extern "C" int
fuzz_hid_read(void *handle, unsigned char *ptr, size_t len, int ms)
{
	size_t n;

	(void)handle;
	(void)ms;

	n = len < wire_len ? len : wire_len;
	memcpy(ptr, wire_ptr, n);
	wire_ptr += n;
	wire_len -= n;

	/* a short read is treated as a transport error by libfido2 */
	return n == len ? (int)n : -1;
}

extern "C" int
fuzz_hid_write(void *handle, const unsigned char *ptr, size_t len)
{
	(void)handle;
	(void)ptr;

	return (int)len;
}

} /* namespace */

/*
 * Substituted for fido_dev_new() when compiling sk-usbhid.c
 * (-Dfido_dev_new=fuzz_fido_dev_new). Returns a fido_dev_t wired up to
 * the fake HID transport above instead of a real USB/HID backend.
 */
extern "C" fido_dev_t *
fuzz_fido_dev_new(void)
{
	fido_dev_t *dev;
	fido_dev_io_t io;

	if ((dev = fido_dev_new()) == NULL)
		return NULL;

	memset(&io, 0, sizeof(io));
	io.open = fuzz_hid_open;
	io.close = fuzz_hid_close;
	io.read = fuzz_hid_read;
	io.write = fuzz_hid_write;

	if (fido_dev_set_io_functions(dev, &io) != FIDO_OK) {
		fido_dev_free(&dev);
		return NULL;
	}

	return dev;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint8_t cdh[32] = {0};	/* client data hash */
	static const uint8_t key_handle[32] = {0};
	struct sk_option dev_opt = { (char *)"device", (char *)"nodev", 0 };
	struct sk_option *options[] = { &dev_opt, NULL };
	struct sk_sign_response *resp = NULL;

	/*
	 * Fixed seed for libfido2's fuzz PRNG/clock. Two things depend on
	 * this PRNG stream:
	 *
	 *  1. fido_dev_open() uses uniform_random() (via
	 *     set_random_report_len() in src/dev.c) to pick dev->rx_len/
	 *     tx_len; we need rx_len == CTAP_MAX_REPORT_LEN (64) to match
	 *     the 64-byte HID report framing of kPrefix below. A different
	 *     rx_len desyncs the fixed CTAPHID_INIT/authenticatorGetInfo
	 *     prefix and fido_dev_open() falls back to U2F.
	 *
	 *  2. prng_init() also flips on fuzz/wrap.c's malloc/calloc/realloc
	 *     failure injection (1/400 chance of returning NULL per call).
	 *     If one of the ~13 allocations libcbor makes while parsing the
	 *     authenticatorGetInfo reply hits that, cbor_load() reports
	 *     CBOR_ERR_MEMERROR, cbor_parse_reply() turns that into
	 *     FIDO_ERR_RX_NOT_CBOR, and fido_dev_open() again falls back to
	 *     U2F -- before ever reaching fido_dev_get_assert()'s CBOR
	 *     parsing, which is the code we want to fuzz.
	 *
	 * Seed 55 was found by brute force to satisfy both constraints:
	 * rx_len == 64 and no allocation-failure during the GetInfo parse,
	 * so fido_dev_open() recognizes CTAP2 and authenticatorGetAssertion
	 * is sent over the CBOR transport.
	 */
	prng_init(55);
	fuzz_clock_reset();

	if (size > kMaxFuzz)
		size = kMaxFuzz;

	memcpy(wire_buf, kPrefix, sizeof(kPrefix));
	memcpy(wire_buf + sizeof(kPrefix), data, size);

	wire_ptr = wire_buf;
	wire_len = sizeof(kPrefix) + size;

	/*
	 * "device=nodev" makes sk_sign() call sk_open() directly, skipping
	 * fido_dev_info_manifest() (real USB enumeration) entirely.
	 */
	sk_sign(SSH_SK_ECDSA, cdh, sizeof(cdh), "ssh:", key_handle,
	    sizeof(key_handle), SSH_SK_USER_PRESENCE_REQD, NULL, options,
	    &resp);

	if (resp != NULL) {
		free(resp->sig_r);
		free(resp->sig_s);
		free(resp);
	}

	return 0;
}
