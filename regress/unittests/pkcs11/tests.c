/*
 * Copyright (c) 2017 Red Hat
 *
 * Authors: Jakub Jelen <jjelen@redhat.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <locale.h>
#include <string.h>

#include "../test_helper/test_helper.h"

#include "sshbuf.h"
#include "ssh-pkcs11-uri.h"

#define EMPTY_URI compose_uri(NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

/* prototypes are not public -- specify them here internally for tests */
struct sshbuf *percent_encode(const char *, size_t, char *);
int percent_decode(char *, char **);

void
compare_uri(struct pkcs11_uri *a, struct pkcs11_uri *b)
{
	ASSERT_PTR_NE(a, NULL);
	ASSERT_PTR_NE(b, NULL);
	ASSERT_SIZE_T_EQ(a->id_len, b->id_len);
	ASSERT_MEM_EQ(a->id, b->id, a->id_len);
	if (b->object != NULL)
		ASSERT_STRING_EQ(a->object, b->object);
	else /* both should be null */
		ASSERT_PTR_EQ(a->object, b->object);
	if (b->module_path != NULL)
		ASSERT_STRING_EQ(a->module_path, b->module_path);
	else /* both should be null */
		ASSERT_PTR_EQ(a->module_path, b->module_path);
	if (b->token != NULL)
		ASSERT_STRING_EQ(a->token, b->token);
	else /* both should be null */
		ASSERT_PTR_EQ(a->token, b->token);
	if (b->manuf != NULL)
		ASSERT_STRING_EQ(a->manuf, b->manuf);
	else /* both should be null */
		ASSERT_PTR_EQ(a->manuf, b->manuf);
	if (b->lib_manuf != NULL)
		ASSERT_STRING_EQ(a->lib_manuf, b->lib_manuf);
	else /* both should be null */
		ASSERT_PTR_EQ(a->lib_manuf, b->lib_manuf);
	if (b->serial != NULL)
		ASSERT_STRING_EQ(a->serial, b->serial);
	else /* both should be null */
		ASSERT_PTR_EQ(a->serial, b->serial);
}

void
check_parse_rv(char *uri, struct pkcs11_uri *expect, int expect_rv)
{
	char *buf = NULL, *str;
	struct pkcs11_uri *pkcs11uri = NULL;
	int rv;

	if (expect_rv == 0)
		str = "Valid";
	else
		str = "Invalid";
	asprintf(&buf, "%s PKCS#11 URI parsing: %s", str, uri);
	TEST_START(buf);
	free(buf);
	pkcs11uri = pkcs11_uri_init();
	rv = pkcs11_uri_parse(uri, pkcs11uri);
	ASSERT_INT_EQ(rv, expect_rv);
	if (rv == 0) /* in case of failure result is undefined */
		compare_uri(pkcs11uri, expect);
	pkcs11_uri_cleanup(pkcs11uri);
	free(expect);
	TEST_DONE();
}

void
check_parse(char *uri, struct pkcs11_uri *expect)
{
	check_parse_rv(uri, expect, 0);
}

struct pkcs11_uri *
compose_uri(unsigned char *id, size_t id_len, char *token, char *lib_manuf,
    char *manuf, char *serial, char *module_path, char *object, char *pin)
{
	struct pkcs11_uri *uri = pkcs11_uri_init();
	if (id_len > 0) {
		uri->id_len = id_len;
		uri->id = id;
	}
	uri->module_path = module_path;
	uri->token = token;
	uri->lib_manuf = lib_manuf;
	uri->manuf = manuf;
	uri->serial = serial;
	uri->object = object;
	uri->pin = pin;
	return uri;
}

static void
test_parse_valid(void)
{
	/* path arguments */
	check_parse("pkcs11:id=%01",
	    compose_uri("\x01", 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL));
	check_parse("pkcs11:id=%00%01",
	    compose_uri("\x00\x01", 2, NULL, NULL, NULL, NULL, NULL, NULL, NULL));
	check_parse("pkcs11:token=SSH%20Keys",
	    compose_uri(NULL, 0, "SSH Keys", NULL, NULL, NULL, NULL, NULL, NULL));
	check_parse("pkcs11:library-manufacturer=OpenSC",
	    compose_uri(NULL, 0, NULL, "OpenSC", NULL, NULL, NULL, NULL, NULL));
	check_parse("pkcs11:manufacturer=piv_II",
	    compose_uri(NULL, 0, NULL, NULL, "piv_II", NULL, NULL, NULL, NULL));
	check_parse("pkcs11:serial=IamSerial",
	    compose_uri(NULL, 0, NULL, NULL, NULL, "IamSerial", NULL, NULL, NULL));
	check_parse("pkcs11:object=SIGN%20Key",
	    compose_uri(NULL, 0, NULL, NULL, NULL, NULL, NULL, "SIGN Key", NULL));
	/* query arguments */
	check_parse("pkcs11:?module-path=/usr/lib64/p11-kit-proxy.so",
	    compose_uri(NULL, 0, NULL, NULL, NULL, NULL, "/usr/lib64/p11-kit-proxy.so", NULL, NULL));
	check_parse("pkcs11:?pin-value=123456",
	    compose_uri(NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, "123456"));

	/* combinations */
	/* ID SHOULD be percent encoded */
	check_parse("pkcs11:token=SSH%20Key;id=0",
	    compose_uri("0", 1, "SSH Key", NULL, NULL, NULL, NULL, NULL, NULL));
	check_parse(
	    "pkcs11:manufacturer=CAC?module-path=/usr/lib64/p11-kit-proxy.so",
	    compose_uri(NULL, 0, NULL, NULL, "CAC", NULL,
	    "/usr/lib64/p11-kit-proxy.so", NULL, NULL));
	check_parse(
	    "pkcs11:object=RSA%20Key?module-path=/usr/lib64/pkcs11/opencryptoki.so",
	    compose_uri(NULL, 0, NULL, NULL, NULL, NULL,
	    "/usr/lib64/pkcs11/opencryptoki.so", "RSA Key", NULL));
	check_parse("pkcs11:?module-path=/usr/lib64/p11-kit-proxy.so&pin-value=123456",
	    compose_uri(NULL, 0, NULL, NULL, NULL, NULL, "/usr/lib64/p11-kit-proxy.so", NULL, "123456"));

	/* empty path component matches everything */
	check_parse("pkcs11:", EMPTY_URI);

	/* empty string is a valid to match against (and different from NULL) */
	check_parse("pkcs11:token=",
	    compose_uri(NULL, 0, "", NULL, NULL, NULL, NULL, NULL, NULL));
	/* Percent character needs to be percent-encoded */
	check_parse("pkcs11:token=%25",
	     compose_uri(NULL, 0, "%", NULL, NULL, NULL, NULL, NULL, NULL));
}

static void
test_parse_invalid(void)
{
	/* Invalid percent encoding */
	check_parse_rv("pkcs11:id=%0", EMPTY_URI, -1);
	/* Invalid percent encoding */
	check_parse_rv("pkcs11:id=%ZZ", EMPTY_URI, -1);
	/* Space MUST be percent encoded -- XXX not enforced yet */
	check_parse("pkcs11:token=SSH Keys",
	    compose_uri(NULL, 0, "SSH Keys", NULL, NULL, NULL, NULL, NULL, NULL));
	/* MUST NOT contain duplicate attributes of the same name */
	check_parse_rv("pkcs11:id=%01;id=%02", EMPTY_URI, -1);
	/* MUST NOT contain duplicate attributes of the same name */
	check_parse_rv("pkcs11:?pin-value=111111&pin-value=123456", EMPTY_URI, -1);
	/* Unrecognized attribute in path are ignored with log message */
	check_parse("pkcs11:key_name=SSH", EMPTY_URI);
	/* Unrecognized attribute in query SHOULD be ignored */
	check_parse("pkcs11:?key_name=SSH", EMPTY_URI);
}

void
check_gen(char *expect, struct pkcs11_uri *uri)
{
	char *buf = NULL, *uri_str;

	asprintf(&buf, "Valid PKCS#11 URI generation: %s", expect);
	TEST_START(buf);
	free(buf);
	uri_str = pkcs11_uri_get(uri);
	ASSERT_PTR_NE(uri_str, NULL);
	ASSERT_STRING_EQ(uri_str, expect);
	free(uri_str);
	TEST_DONE();
}

static void
test_generate_valid(void)
{
	/* path arguments */
	check_gen("pkcs11:id=%01",
	    compose_uri("\x01", 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL));
	check_gen("pkcs11:id=%00%01",
	    compose_uri("\x00\x01", 2, NULL, NULL, NULL, NULL, NULL, NULL, NULL));
	check_gen("pkcs11:token=SSH%20Keys", /* space must be percent encoded */
	    compose_uri(NULL, 0, "SSH Keys", NULL, NULL, NULL, NULL, NULL, NULL));
	/* library-manufacturer is not implmented now */
	/*check_gen("pkcs11:library-manufacturer=OpenSC",
	    compose_uri(NULL, 0, NULL, "OpenSC", NULL, NULL, NULL, NULL, NULL));*/
	check_gen("pkcs11:manufacturer=piv_II",
	    compose_uri(NULL, 0, NULL, NULL, "piv_II", NULL, NULL, NULL, NULL));
	check_gen("pkcs11:serial=IamSerial",
	    compose_uri(NULL, 0, NULL, NULL, NULL, "IamSerial", NULL, NULL, NULL));
	check_gen("pkcs11:object=RSA%20Key",
	    compose_uri(NULL, 0, NULL, NULL, NULL, NULL, NULL, "RSA Key", NULL));
	/* query arguments */
	check_gen("pkcs11:?module-path=/usr/lib64/p11-kit-proxy.so",
	    compose_uri(NULL, 0, NULL, NULL, NULL, NULL, "/usr/lib64/p11-kit-proxy.so", NULL, NULL));

	/* combinations */
	check_gen("pkcs11:id=%02;token=SSH%20Keys",
	    compose_uri("\x02", 1, "SSH Keys", NULL, NULL, NULL, NULL, NULL, NULL));
	check_gen("pkcs11:id=%EE%02?module-path=/usr/lib64/p11-kit-proxy.so",
	    compose_uri("\xEE\x02", 2, NULL, NULL, NULL, NULL, "/usr/lib64/p11-kit-proxy.so", NULL, NULL));
	check_gen("pkcs11:object=Encryption%20Key;manufacturer=piv_II",
	    compose_uri(NULL, 0, NULL, NULL, "piv_II", NULL, NULL, "Encryption Key", NULL));

	/* empty path component matches everything */
	check_gen("pkcs11:", EMPTY_URI);

}

void
check_encode(char *source, size_t len, char *allow_list, char *expect)
{
	char *buf = NULL;
	struct sshbuf *b;

	asprintf(&buf, "percent_encode: expected %s", expect);
	TEST_START(buf);
	free(buf);

	b = percent_encode(source, len, allow_list);
	ASSERT_STRING_EQ(sshbuf_ptr(b), expect);
	sshbuf_free(b);
	TEST_DONE();
}

static void
test_percent_encode_multibyte(void)
{
	/* SHOULD be encoded as octets according to the UTF-8 character encoding */

	/* multi-byte characters are "for free" */
	check_encode("$", 1, "", "%24");
	check_encode("¢", 2, "", "%C2%A2");
	check_encode("€", 3, "", "%E2%82%AC");
	check_encode("𐍈", 4, "", "%F0%90%8D%88");

	/* CK_UTF8CHAR is unsigned char (1 byte) */
	/* labels SHOULD be normalized to NFC [UAX15] */

}

static void
test_percent_encode(void)
{
	/* Without allow list encodes everything (for CKA_ID) */
	check_encode("A*", 2, "", "%41%2A");
	check_encode("\x00", 1, "", "%00");
	check_encode("\x7F", 1, "", "%7F");
	check_encode("\x80", 1, "", "%80");
	check_encode("\xff", 1, "", "%FF");

	/* Default allow list encodes anything but safe letters */
	check_encode("test" "\x00" "0alpha", 11, PKCS11_URI_WHITELIST,
	    "test%000alpha");
	check_encode(" ", 1, PKCS11_URI_WHITELIST,
	    "%20"); /* Space MUST be percent encoded */
	check_encode("/", 1, PKCS11_URI_WHITELIST,
	    "%2F"); /* '/' delimiter MUST be percent encoded (in the path) */
	check_encode("?", 1, PKCS11_URI_WHITELIST,
	    "%3F"); /* delimiter '?' MUST be percent encoded (in the path) */
	check_encode("#", 1, PKCS11_URI_WHITELIST,
	    "%23"); /* '#' MUST be always percent encoded */
	check_encode("key=value;separator?query&amp;#anch", 35, PKCS11_URI_WHITELIST,
	    "key%3Dvalue%3Bseparator%3Fquery%26amp%3B%23anch");

	/* Components in query can have '/' unencoded (useful for paths) */
	check_encode("/path/to.file", 13, PKCS11_URI_WHITELIST "/",
	    "/path/to.file");
}

void
check_decode(char *source, char *expect, int expect_len)
{
	char *buf = NULL, *out = NULL;
	int rv;

	asprintf(&buf, "percent_decode: %s", source);
	TEST_START(buf);
	free(buf);

	rv = percent_decode(source, &out);
	ASSERT_INT_EQ(rv, expect_len);
	if (rv >= 0)
		ASSERT_MEM_EQ(out, expect, expect_len);
	free(out);
	TEST_DONE();
}

static void
test_percent_decode(void)
{
	/* simple valid cases */
	check_decode("%00", "\x00", 1);
	check_decode("%FF", "\xFF", 1);

	/* normal strings shold be kept intact */
	check_decode("strings are left", "strings are left", 16);
	check_decode("10%25 of trees", "10% of trees", 12);

	/* make sure no more than 2 bytes are parsed */
	check_decode("%222", "\x22" "2", 2);

	/* invalid expects failure */
	check_decode("%0", "", -1);
	check_decode("%Z", "", -1);
	check_decode("%FG", "", -1);
}

void
tests(void)
{
	test_percent_encode();
	test_percent_encode_multibyte();
	test_percent_decode();
	test_parse_valid();
	test_parse_invalid();
	test_generate_valid();
}

void
benchmarks(void)
{
	printf("no benchmarks\n");
}

