/*
 * Copyright (c) 2020 Damien Miller
 * Copyright (c) 2021 Yuichiro Naito
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

#define SSHBUF_INTERNAL
#include "includes.h"

#include <sys/types.h>

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#include "xmalloc.h"
#include "ssherr.h"
#include "sshbuf.h"

#define PUTPW(b, id) \
	do { \
		if ((r = sshbuf_put_string(b, \
		    &pwent->id, sizeof(pwent->id))) != 0) \
			goto err;  \
	} while (0)

/*
 * store struct pwd
 */
int
sshbuf_put_passwd(struct sshbuf *buf, const struct passwd *pwent)
{
	int r;

	/*
	 * We never send pointer values of struct passwd.
	 * It is safe from wild pointer even if a new pointer member is added.
	 */

	PUTPW(buf, pw_uid);
	PUTPW(buf, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(buf, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(buf, pw_expire);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_FIELDS
	PUTPW(buf, pw_fields);
#endif

	if ((r = sshbuf_put_cstring(buf, pwent->pw_name)) != 0 ||
	    (r = sshbuf_put_cstring(buf, "*")) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_put_cstring(buf, pwent->pw_gecos)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_put_cstring(buf, pwent->pw_class)) != 0 ||
#endif
	    (r = sshbuf_put_cstring(buf, pwent->pw_dir)) != 0 ||
	    (r = sshbuf_put_cstring(buf, pwent->pw_shell)) != 0)
		goto err;

	return 0;

err:
	return r;
}

#define GETPW(b, id) \
	do { \
		if ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			goto err; \
		if (len != sizeof(pw->id)) \
			goto err; \
		memcpy(&pw->id, p, len); \
	} while (0)

/*
 * extract struct pwd
 */
struct passwd *
sshbuf_get_passwd(struct sshbuf *buf)
{
	struct passwd *pw;
	size_t len;
	int r;
	const u_char *p;

	pw = xcalloc(1, sizeof(*pw));
	GETPW(buf, pw_uid);
	GETPW(buf, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(buf, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(buf, pw_expire);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_FIELDS
	GETPW(buf, pw_fields);
#endif

	if ((r = sshbuf_get_cstring(buf, &pw->pw_name, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &pw->pw_passwd, NULL)) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(buf, &pw->pw_gecos, NULL)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(buf, &pw->pw_class, NULL)) != 0 ||
#endif
	    (r = sshbuf_get_cstring(buf, &pw->pw_dir, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &pw->pw_shell, NULL)) != 0)
		goto err;

	return pw;
err:
	sshbuf_free_passwd(pw);
	return NULL;
}

/*
 * free struct passwd obtained from sshbuf_get_passwd.
 */
void
sshbuf_free_passwd(struct passwd *pwent)
{
	if (pwent == NULL)
		return;
	free(pwent->pw_shell);
	free(pwent->pw_dir);
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	free(pwent->pw_class);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	free(pwent->pw_gecos);
#endif
	free(pwent->pw_passwd);
	free(pwent->pw_name);
	free(pwent);
}
