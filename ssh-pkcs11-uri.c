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

#ifdef ENABLE_PKCS11

#include <stdio.h>
#include <string.h>

#include "sshkey.h"
#include "sshbuf.h"
#include "log.h"

#define CRYPTOKI_COMPAT
#include "pkcs11.h"

#include "ssh-pkcs11-uri.h"

#define PKCS11_URI_PATH_SEPARATOR ";"
#define PKCS11_URI_QUERY_SEPARATOR "&"
#define PKCS11_URI_VALUE_SEPARATOR "="
#define PKCS11_URI_ID "id"
#define PKCS11_URI_TOKEN "token"
#define PKCS11_URI_OBJECT "object"
#define PKCS11_URI_LIB_MANUF "library-manufacturer"
#define PKCS11_URI_MANUF "manufacturer"
#define PKCS11_URI_SERIAL "serial"
#define PKCS11_URI_MODULE_PATH "module-path"
#define PKCS11_URI_PIN_VALUE "pin-value"

/* Keyword tokens. */
typedef enum {
	pId, pToken, pObject, pLibraryManufacturer, pManufacturer, pSerial,
	pModulePath, pPinValue, pBadOption
} pkcs11uriOpCodes;

/* Textual representation of the tokens. */
static struct {
	const char *name;
	pkcs11uriOpCodes opcode;
} keywords[] = {
	{ PKCS11_URI_ID, pId },
	{ PKCS11_URI_TOKEN, pToken },
	{ PKCS11_URI_OBJECT, pObject },
	{ PKCS11_URI_LIB_MANUF, pLibraryManufacturer },
	{ PKCS11_URI_MANUF, pManufacturer },
	{ PKCS11_URI_SERIAL, pSerial },
	{ PKCS11_URI_MODULE_PATH, pModulePath },
	{ PKCS11_URI_PIN_VALUE, pPinValue },
	{ NULL, pBadOption }
};

static pkcs11uriOpCodes
parse_token(const char *cp)
{
	u_int i;

	for (i = 0; keywords[i].name; i++)
		if (strncasecmp(cp, keywords[i].name,
		    strlen(keywords[i].name)) == 0)
			return keywords[i].opcode;

	return pBadOption;
}

int
percent_decode(char *data, char **outp)
{
	char tmp[3];
	char *out, *tmp_end;
	char *p = data;
	long value;
	size_t outlen = 0;

	out = malloc(strlen(data)+1); /* upper bound */
	if (out == NULL)
		return -1;
	while (*p != '\0') {
		switch (*p) {
		case '%':
			p++;
			if (*p == '\0')
				goto fail;
			tmp[0] = *p++;
			if (*p == '\0')
				goto fail;
			tmp[1] = *p++;
			tmp[2] = '\0';
			tmp_end = NULL;
			value = strtol(tmp, &tmp_end, 16);
			if (tmp_end != tmp+2)
				goto fail;
			else
				out[outlen++] = (char) value;
			break;
		default:
			out[outlen++] = *p++;
			break;
		}
	}

	/* zero terminate */
	out[outlen] = '\0';
	*outp = out;
	return outlen;
fail:
	free(out);
	return -1;
}

struct sshbuf *
percent_encode(const char *data, size_t length, const char *allow_list)
{
	struct sshbuf *b = NULL;
	char tmp[4], *cp;
	size_t i;

	if ((b = sshbuf_new()) == NULL)
		return NULL;
	for (i = 0; i < length; i++) {
		cp = strchr(allow_list, data[i]);
		/* if c is specified as '\0' pointer to terminator is returned !! */
		if (cp != NULL && *cp != '\0') {
			if (sshbuf_put(b, &data[i], 1) != 0)
				goto err;
		} else
			if (snprintf(tmp, 4, "%%%02X", (unsigned char) data[i]) < 3
			    || sshbuf_put(b, tmp, 3) != 0)
				goto err;
	}
	if (sshbuf_put(b, "\0", 1) == 0)
		return b;
err:
	sshbuf_free(b);
	return NULL;
}

char *
pkcs11_uri_append(char *part, const char *separator, const char *key,
    struct sshbuf *value)
{
	char *new_part;
	size_t size = 0;

	if (value == NULL)
		return NULL;

	size = asprintf(&new_part,
	    "%s%s%s"  PKCS11_URI_VALUE_SEPARATOR "%s",
	    (part != NULL ? part : ""),
	    (part != NULL ? separator : ""),
	    key, sshbuf_ptr(value));
	sshbuf_free(value);
	free(part);

	if (size <= 0)
		return NULL;
	return new_part;
}

char *
pkcs11_uri_get(struct pkcs11_uri *uri)
{
	size_t size = 0;
	char *p = NULL, *path = NULL, *query = NULL;

	/* compose a percent-encoded ID */
	if (uri->id_len > 0) {
		struct sshbuf *key_id = percent_encode(uri->id, uri->id_len, "");
		path = pkcs11_uri_append(path, PKCS11_URI_PATH_SEPARATOR,
		    PKCS11_URI_ID, key_id);
		if (path == NULL)
			goto err;
	}

	/* Write object label */
	if (uri->object) {
		struct sshbuf *label = percent_encode(uri->object, strlen(uri->object),
		    PKCS11_URI_WHITELIST);
		path = pkcs11_uri_append(path, PKCS11_URI_PATH_SEPARATOR,
		    PKCS11_URI_OBJECT, label);
		if (path == NULL)
			goto err;
	}

	/* Write token label */
	if (uri->token) {
		struct sshbuf *label = percent_encode(uri->token, strlen(uri->token),
		    PKCS11_URI_WHITELIST);
		path = pkcs11_uri_append(path, PKCS11_URI_PATH_SEPARATOR,
		    PKCS11_URI_TOKEN, label);
		if (path == NULL)
			goto err;
	}

	/* Write manufacturer */
	if (uri->manuf) {
		struct sshbuf *manuf = percent_encode(uri->manuf,
		    strlen(uri->manuf), PKCS11_URI_WHITELIST);
		path = pkcs11_uri_append(path, PKCS11_URI_PATH_SEPARATOR,
		    PKCS11_URI_MANUF, manuf);
		if (path == NULL)
			goto err;
	}

	/* Write serial */
	if (uri->serial) {
		struct sshbuf *serial = percent_encode(uri->serial,
		    strlen(uri->serial), PKCS11_URI_WHITELIST);
		path = pkcs11_uri_append(path, PKCS11_URI_PATH_SEPARATOR,
		    PKCS11_URI_SERIAL, serial);
		if (path == NULL)
			goto err;
	}

	/* Write module_path */
	if (uri->module_path) {
		struct sshbuf *module = percent_encode(uri->module_path,
		    strlen(uri->module_path), PKCS11_URI_WHITELIST "/");
		query = pkcs11_uri_append(query, PKCS11_URI_QUERY_SEPARATOR,
		    PKCS11_URI_MODULE_PATH, module);
		if (query == NULL)
			goto err;
	}

	size = asprintf(&p, PKCS11_URI_SCHEME "%s%s%s",
	    path != NULL ? path : "",
	    query != NULL ? "?" : "",
	    query != NULL ? query : "");
err:
	free(query);
	free(path);
	if (size <= 0)
		return NULL;
	return p;
}

struct pkcs11_uri *
pkcs11_uri_init()
{
	struct pkcs11_uri *d = calloc(1, sizeof(struct pkcs11_uri));
	return d;
}

void
pkcs11_uri_cleanup(struct pkcs11_uri *pkcs11)
{
	if (pkcs11 == NULL) {
		return;
	}

	free(pkcs11->id);
	free(pkcs11->module_path);
	free(pkcs11->token);
	free(pkcs11->object);
	free(pkcs11->lib_manuf);
	free(pkcs11->manuf);
	free(pkcs11->serial);
	if (pkcs11->pin)
		freezero(pkcs11->pin, strlen(pkcs11->pin));
	free(pkcs11);
}

int
pkcs11_uri_parse(const char *uri, struct pkcs11_uri *pkcs11)
{
	char *saveptr1, *saveptr2, *str1, *str2, *tok;
	int rv = 0, len;
	char *p = NULL;

	size_t scheme_len = strlen(PKCS11_URI_SCHEME);
	if (strlen(uri) < scheme_len || /* empty URI matches everything */
	    strncmp(uri, PKCS11_URI_SCHEME, scheme_len) != 0) {
		error_f("The '%s' does not look like PKCS#11 URI", uri);
		return -1;
	}

	if (pkcs11 == NULL) {
		error_f("Bad arguments. The pkcs11 can't be null");
		return -1;
	}

	/* skip URI schema name */
	p = strdup(uri);
	str1 = p;

	/* everything before ? */
	tok = strtok_r(str1, "?", &saveptr1);
	if (tok == NULL) {
		error_f("pk11-path expected, got EOF");
		rv = -1;
		goto out;
	}

	/* skip URI schema name:
	 * the scheme ensures that there is at least something before "?"
	 * allowing empty pk11-path. Resulting token at worst pointing to
	 * \0 byte */
	tok = tok + scheme_len;

	/* parse pk11-path */
	for (str2 = tok; ; str2 = NULL) {
		char **charptr, *arg = NULL;
		pkcs11uriOpCodes opcode;
		tok = strtok_r(str2, PKCS11_URI_PATH_SEPARATOR, &saveptr2);
		if (tok == NULL)
			break;
		opcode = parse_token(tok);
		if (opcode != pBadOption)
			arg = tok + strlen(keywords[opcode].name) + 1; /* separator "=" */

		switch (opcode) {
		case pId:
			/* CKA_ID */
			if (pkcs11->id != NULL) {
				verbose_f("The id already set in the PKCS#11 URI");
				rv = -1;
				goto out;
			}
			len = percent_decode(arg, &pkcs11->id);
			if (len <= 0) {
				verbose_f("Failed to percent-decode CKA_ID: %s", arg);
				rv = -1;
				goto out;
			} else
				pkcs11->id_len = len;
			debug3_f("Setting CKA_ID = %s from PKCS#11 URI", arg);
			break;
		case pToken:
			/* CK_TOKEN_INFO -> label */
			charptr = &pkcs11->token;
 parse_string:
			if (*charptr != NULL) {
				verbose_f("The %s already set in the PKCS#11 URI",
				    keywords[opcode].name);
				rv = -1;
				goto out;
			}
			percent_decode(arg, charptr);
			debug3_f("Setting %s = %s from PKCS#11 URI",
			    keywords[opcode].name, *charptr);
			break;

		case pObject:
			/* CK_TOKEN_INFO -> manufacturerID */
			charptr = &pkcs11->object;
			goto parse_string;

		case pManufacturer:
			/* CK_TOKEN_INFO -> manufacturerID */
			charptr = &pkcs11->manuf;
			goto parse_string;

		case pSerial:
			/* CK_TOKEN_INFO -> serialNumber */
			charptr = &pkcs11->serial;
			goto parse_string;

		case pLibraryManufacturer:
			/* CK_INFO -> manufacturerID */
			charptr = &pkcs11->lib_manuf;
			goto parse_string;

		default:
			/* Unrecognized attribute in the URI path SHOULD be error */
			verbose_f("Unknown part of path in PKCS#11 URI: %s", tok);
		}
	}

	tok = strtok_r(NULL, "?", &saveptr1);
	if (tok == NULL) {
		goto out;
	}
	/* parse pk11-query (optional) */
	for (str2 = tok; ; str2 = NULL) {
		char *arg;
		pkcs11uriOpCodes opcode;
		tok = strtok_r(str2, PKCS11_URI_QUERY_SEPARATOR, &saveptr2);
		if (tok == NULL)
			break;
		opcode = parse_token(tok);
		if (opcode != pBadOption)
			arg = tok + strlen(keywords[opcode].name) + 1; /* separator "=" */

		switch (opcode) {
		case pModulePath:
			/* module-path is PKCS11Provider */
			if (pkcs11->module_path != NULL) {
				verbose_f("Multiple module-path attributes are"
				    "not supported the PKCS#11 URI");
				rv = -1;
				goto out;
			}
			percent_decode(arg, &pkcs11->module_path);
			debug3_f("Setting PKCS11Provider = %s from PKCS#11 URI",
			    pkcs11->module_path);
			break;

		case pPinValue:
			/* pin-value */
			if (pkcs11->pin != NULL) {
				verbose_f("Multiple pin-value attributes are"
				    "not supported the PKCS#11 URI");
				rv = -1;
				goto out;
			}
			percent_decode(arg, &pkcs11->pin);
			debug3_f("Setting PIN from PKCS#11 URI");
			break;

		default:
			/* Unrecognized attribute in the URI query SHOULD be ignored */
			verbose_f("Unknown part of query in PKCS#11 URI: %s", tok);
		}
	}
out:
	free(p);
	return rv;
}

#endif /* ENABLE_PKCS11 */
