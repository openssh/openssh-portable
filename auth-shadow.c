/*
 * Copyright (c) 2004 Darren Tucker.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"
RCSID("$Id: auth-shadow.c,v 1.1 2004/02/10 02:01:14 dtucker Exp $");

#ifdef USE_SHADOW
#include <shadow.h>

#include "auth.h"
#include "auth-shadow.h"
#include "buffer.h"
#include "log.h"

#define DAY	(24L * 60 * 60) /* 1 day in seconds */

extern Buffer loginmsg;

/*
 * Checks password expiry for platforms that use shadow passwd files.
 * Returns: 1 = password expired, 0 = password not expired
 */
int
auth_shadow_pwexpired(Authctxt *ctxt)
{
	struct spwd *spw = NULL;
	const char *user = ctxt->pw->pw_name;
	time_t today;

	if ((spw = getspnam(user)) == NULL) {
		error("Could not get shadow information for %.100s", user);
		return 0;
	}

	today = time(NULL) / DAY;
	debug3("%s: today %d sp_lstchg %d sp_max %d", __func__, (int)today,
	    (int)spw->sp_lstchg, (int)spw->sp_max);

#if defined(__hpux) && !defined(HAVE_SECUREWARE)
	if (iscomsec() && spw->sp_min == 0 && spw->sp_max == 0 &&
	    spw->sp_warn == 0)
		return 0;	/* HP-UX Trusted Mode: expiry disabled */
#endif

	/* TODO: Add code to put expiry warnings into loginmsg */

	if (spw->sp_lstchg == 0) {
		logit("User %.100s password has expired (root forced)", user);
		return 1;
	}

	if (spw->sp_max != -1 && today > spw->sp_lstchg + spw->sp_max) {
		logit("User %.100s password has expired (password aged)", user);
		return 1;
	}

	return 0;
}
#endif	/* USE_SHADOW */
