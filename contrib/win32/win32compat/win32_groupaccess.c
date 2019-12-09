/*
 *
 * Author: Manoj Ampalam <manoj.ampalam@microsoft.com> 
 *   groupaccess interface implementation for Windows
 *
 * Author: Bryan Berns <berns@uwalumni.com>
 *   Added support for running configuration rules against nested groups 
 *   spawning multiple domains/forests.
 *   Core logic implemented in get_user_groups()
 *
 * Copyright (c) 2018 Microsoft Corp.
 * All rights reserved
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

#define UMDF_USING_NTSTATUS 
#define SECURITY_WIN32
#include <Windows.h>
#include <LM.h>
#include <Sddl.h>
#include <Aclapi.h>
#include <Ntsecapi.h>
#include <security.h>
#include <ntstatus.h>

#define __attribute__(a)
#include "inc/sys/types.h"
#include "..\..\..\xmalloc.h"
#include "..\..\..\groupaccess.h"
#include "..\..\..\match.h"
#include "..\..\..\log.h"

#include "misc_internal.h"

static int ngroups;
static char **groups_byname;
static char *user_name;
static HANDLE user_token;

/*
* This method will fetch all the groups (listed below) even if the user is indirectly a member.
* - Local machine groups
* - Domain groups
* - global group
* - universal groups
*/
static int
get_user_groups()
{
	/* early declarations and initializations to support cleanup */
	HANDLE logon_token = user_token;
	PTOKEN_GROUPS group_buf = NULL;
	int ret = -1, num_groups = 0;
	static int processed = 0;

	if (processed)
		return 0;

	/* initialize return values */
	errno = 0;
	char ** user_groups = NULL;

	debug2("%s: extracting all groups of user %s", __func__, user_name);

	/* fetch the computer name so we can determine if the specified user is local or not */
	wchar_t computer_name[CNLEN + 1];
	DWORD computer_name_size = ARRAYSIZE(computer_name);
	if (GetComputerNameW(computer_name, &computer_name_size) == 0)  {
		debug3("%s: GetComputerNameW() failed: %d", __FUNCTION__, GetLastError());
		errno = EOTHER;
		goto cleanup;
	}

	/* allocate area for group information */
	DWORD group_size = 0;
	if (GetTokenInformation(logon_token, TokenGroups, NULL, 0, &group_size) == 0
		&& GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
		(group_buf = (PTOKEN_GROUPS)malloc(group_size)) == NULL) {
		debug3("%s: GetTokenInformation() failed: %d", __FUNCTION__, GetLastError());
		errno = EOTHER;
		goto cleanup;
	}

	/* read group sids from logon token -- this will return a list of groups
	* similar to the data returned when you do a whoami /groups command */
	if (GetTokenInformation(logon_token, TokenGroups, group_buf, group_size, &group_size) == 0) {
		debug3("%s: GetTokenInformation() failed with error %d", __FUNCTION__, GetLastError());
		errno = EOTHER;
		goto cleanup;
	}

	/* allocate memory to hold points to all group names */
	if ((user_groups = (char**)malloc(sizeof(char*) * group_buf->GroupCount)) == NULL) {
		errno = ENOMEM;
		goto cleanup;
	}

	for (DWORD i = 0; i < group_buf->GroupCount; i++) {
		/* only bother with group thats are 'enabled' from a security perspective */
		if ((group_buf->Groups[i].Attributes & SE_GROUP_ENABLED) == 0 ||
			!IsValidSid(group_buf->Groups[i].Sid))
			continue;

		/* only bother with groups that are builtin or classic domain/local groups */
		SID * sid = group_buf->Groups[i].Sid;
		DWORD sub = sid->SubAuthority[0];
		SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
		if (memcmp(&nt_authority, GetSidIdentifierAuthority(sid), sizeof(SID_IDENTIFIER_AUTHORITY)) == 0 && (
			sub == SECURITY_NT_NON_UNIQUE || sub == SECURITY_BUILTIN_DOMAIN_RID)) {

			/* lookup the account name for this sid */
			wchar_t name[GNLEN + 1];
			DWORD name_len = ARRAYSIZE(name);
			wchar_t domain[DNLEN + 1];
			DWORD domain_len = ARRAYSIZE(domain);
			SID_NAME_USE name_use = 0;
			if (LookupAccountSidW(NULL, sid, name, &name_len, domain, &domain_len, &name_use) == 0) {
				errno = ENOENT;
				debug("%s: LookupAccountSid() failed: %d.", __FUNCTION__, GetLastError());
				goto cleanup;
			}

			int current_group = num_groups++;
			wchar_t formatted_group[DNLEN + 1 + GNLEN + 1];
			/* for local accounts trim the domain qualifier */
			if (sub == SECURITY_BUILTIN_DOMAIN_RID || _wcsicmp(computer_name, domain) == 0)
				swprintf_s(formatted_group, ARRAYSIZE(formatted_group), L"%s", name);
			else /* add group name in netbios\\name format */
				swprintf_s(formatted_group, ARRAYSIZE(formatted_group), L"%s\\%s", domain, name);
			
			_wcslwr_s(formatted_group, ARRAYSIZE(formatted_group));
			debug3("Added group '%ls' for user %s", formatted_group, user_name);
			user_groups[current_group] = utf16_to_utf8(formatted_group);
			if (user_groups[current_group] == NULL) {
				errno = ENOMEM;
				goto cleanup;
			}
		}
	}


	ngroups = num_groups;
	/* downsize the array to the actual size */
	groups_byname = (char**)realloc(user_groups, sizeof(char*) * num_groups);;
	user_groups = NULL;
	ret = 0;

cleanup:
	if (group_buf)
		free(group_buf);

	if (user_groups && num_groups) {
		for (int group = 0; group < num_groups; group++)
			if (user_groups[group]) free(user_groups[group]);
		free(user_groups);
	}

	debug2("%s: done extracting all groups of user %s", __func__, user_name);
	processed = 1;
	return ret;
}

/* 
 *
 * checks if user_token has "group" membership, fatal exits on error 
 * returns 1 if true, 0 otherwise
 */
static int
check_group_membership(const char* group)
{
	PSID sid = NULL;
	BOOL is_member = 0;
	
	if ((sid = get_sid(group)) == NULL) {
		error("unable to resolve group %s", group);
		goto cleanup;
	}
	
	if (!CheckTokenMembership(user_token, sid, &is_member))
		fatal("%s CheckTokenMembership for user %s failed with %d for group %s", __func__, user_name, GetLastError(), group);

cleanup:
	if (sid)
		free(sid);
	return is_member? 1: 0;
}


/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
int
ga_init(const char *user, gid_t base)
{
	ngroups = 0;
	groups_byname = NULL;
	user_token = NULL;

	user_name = xstrdup(user);

	if ((user_token = get_user_token(user_name, 0)) == NULL) {
		/*
		 * TODO - We need to fatal() all the times when we fail to generate the user token.
		 */
		if (get_custom_lsa_package()) {
			error("%s, unable to resolve user %s", __func__, user_name);
			return 0;
		} else {
			fatal("%s, unable to resolve user %s", __func__, user_name);
		}
	}
		
	/* 
	 * supposed to retun number of groups associated with user 
	 * since we do lazy group evaluation, returning 1 here
	 */

	return 1;
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
int
ga_match(char * const *groups, int n)
{
	int i, j;

	/* group retrieval is expensive, optmizing the common case scenario with no wild cards */
	for (j = 0; j < n; j++)
		if (strchr(groups[j], '?') || strchr(groups[j], '*'))
			goto fetch_all;

	for (j = 0; j < n; j++)
		if (check_group_membership(groups[j]))
			return 1;

	return 0;

fetch_all:
	if (get_user_groups() == -1)
		fatal("unable to retrieve group info for user %s", user_name);

	for (i = 0; i < ngroups; i++)
		for (j = 0; j < n; j++)
			if (match_pattern(groups_byname[i], groups[j]))
				return 1;
	return 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
int
ga_match_pattern_list(const char *group_pattern)
{
	int i, found = 0;
	char *tmp = NULL;

	/* group retrieval is expensive, optmizing the common case scenario - only one group with no wild cards and no negation */
	if (!strchr(group_pattern, ',') && !strchr(group_pattern, '?') && 
	    !strchr(group_pattern, '*') && !strchr(group_pattern, '!'))
		return check_group_membership(group_pattern);

	if (get_user_groups() == -1)
		fatal("unable to retrieve group info for user %s", user_name);

	/* For domain groups we need special handling.
	 * We support both "domain\group_name" and "domain/group_name" formats.
	 */
	if (tmp = strstr(group_pattern, "/"))
		*tmp = '\\';

	for (i = 0; i < ngroups; i++) {
		/* Group names are case insensitive */
		switch (match_pattern_list(groups_byname[i], group_pattern, 1)) {
		case -1:
			return 0;	/* Negated match wins */
		case 0:
			continue;
		case 1:
			found = 1;
		}
	}
	return found;
}

/*
 * Free memory allocated for group access list.
 */
void
ga_free(void)
{
	int i;

	if (ngroups > 0) {
		for (i = 0; i < ngroups; i++)
			free(groups_byname[i]);
		ngroups = 0;
		free(groups_byname);
	}
	groups_byname = NULL;

	if (user_name)
		free(user_name);
	user_name = NULL;
	CloseHandle(user_token);
	user_token = NULL;
}