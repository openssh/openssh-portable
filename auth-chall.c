/*
 * Copyright (c) 2001 Markus Friedl. All rights reserved.
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
RCSID("$OpenBSD: auth-chall.c,v 1.4 2001/02/04 15:32:22 stevesk Exp $");

#include "auth.h"

#ifdef SKEY
#include <skey.h>

char *
get_challenge(Authctxt *authctxt, char *devs)
{
	static char challenge[1024];
	struct skey skey;
	if (skeychallenge(&skey, authctxt->user, challenge) == -1)
		return NULL;
	strlcat(challenge, "\nS/Key Password: ", sizeof challenge);
	return challenge;
}
int
verify_response(Authctxt *authctxt, char *response)
{
	return (authctxt->valid &&
	    skey_haskey(authctxt->pw->pw_name) == 0 &&
	    skey_passcheck(authctxt->pw->pw_name, response) != -1);
}
#else
/* not available */
char *
get_challenge(Authctxt *authctxt, char *devs)
{
	return NULL;
}
int
verify_response(Authctxt *authctxt, char *response)
{
	return 0;
}
#endif
