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

#define PKCS11_URI_SCHEME "pkcs11:"
#define PKCS11_URI_WHITELIST	"abcdefghijklmnopqrstuvwxyz" \
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
				"0123456789_-.()"

struct pkcs11_uri {
	/* path */
	char *id;
	size_t id_len;
	char *token;
	char *object;
	char *lib_manuf;
	char *manuf;
	char *serial;
	/* query */
	char *module_path;
	char *pin; /* Only parsed, but not printed */
};

struct	 pkcs11_uri *pkcs11_uri_init();
void	 pkcs11_uri_cleanup(struct pkcs11_uri *);
int	 pkcs11_uri_parse(const char *, struct pkcs11_uri *);
struct	 pkcs11_uri *pkcs11_uri_init();
char	*pkcs11_uri_get(struct pkcs11_uri *uri);

