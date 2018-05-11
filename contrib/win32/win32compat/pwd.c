/*
 * Author: NoMachine <developers@nomachine.com>
 *
 * Author: Bryan Berns <berns@uwalumni.com>
 *   Normalized and optimized login routines and added support for
 *   internet-linked accounts.
 *
 * Copyright (c) 2009, 2011 NoMachine
 * All rights reserved
 *
 * Support functions and system calls' replacements needed to let the
 * software run on Win32 based operating systems.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
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

#include <Windows.h>
#include <stdio.h>
#include <LM.h>
#include <sddl.h>
#include <DsGetDC.h>
#define SECURITY_WIN32
#include <security.h>

#include "inc\pwd.h"
#include "inc\grp.h"
#include "inc\utf.h"
#include "misc_internal.h"
#include "debug.h"

static struct passwd pw;
static char* pw_shellpath = NULL;
#define SHELL_HOST "\\ssh-shellhost.exe"


int
initialize_pw()
{
	errno_t r = 0;
	char* program_dir = w32_programdir();
	size_t program_dir_len = strlen(program_dir);
	size_t shell_host_len = strlen(SHELL_HOST);
	if (pw_shellpath == NULL) {
		if ((pw_shellpath = malloc(program_dir_len + shell_host_len + 1)) == NULL)
			fatal("initialize_pw - out of memory");
		else {
			char* head = pw_shellpath;
			if ((r= memcpy_s(head, program_dir_len + shell_host_len + 1, w32_programdir(), program_dir_len)) != 0) {
				fatal("memcpy_s failed with error: %d.", r);
			}
			head += program_dir_len;
			if ((r = memcpy_s(head, shell_host_len + 1, SHELL_HOST, shell_host_len)) != 0) {
				fatal("memcpy_s failed with error: %d.", r);
			}
			head += shell_host_len;
			*head = '\0';
		}
	}

	if (pw.pw_shell != pw_shellpath) {
		memset(&pw, 0, sizeof(pw));
		pw.pw_shell = pw_shellpath;
		pw.pw_passwd = "\0";
		/* pw_uid = 0 for root on Unix and SSH code has specific restrictions for root
		 * that are not applicable in Windows */
		pw.pw_uid = 1;
	}
	return 0;
}

void
reset_pw()
{
	initialize_pw();
	if (pw.pw_name)
		free(pw.pw_name);
	if (pw.pw_dir)
		free(pw.pw_dir);
	if (pw.pw_sid)
		free(pw.pw_sid);
	pw.pw_name = NULL;
	pw.pw_dir = NULL;
	pw.pw_sid = NULL;
}

static struct passwd*
get_passwd(const wchar_t * user_utf16, PSID sid)
{
	wchar_t user_resolved[DNLEN + 1 + UNLEN + 1];
	struct passwd *ret = NULL;
	wchar_t *sid_string = NULL;
	wchar_t reg_path[PATH_MAX], profile_home[PATH_MAX], profile_home_exp[PATH_MAX];
	DWORD reg_path_len = PATH_MAX;
	HKEY reg_key = 0;	
	
	BYTE binary_sid[SECURITY_MAX_SID_SIZE];
	DWORD sid_size = ARRAYSIZE(binary_sid);
	WCHAR domain_name[DNLEN + 1] = L"";
	DWORD domain_name_size = DNLEN + 1;
	SID_NAME_USE account_type = 0;

	errno = 0;
	reset_pw();

	/* skip forward lookup on name if sid was passed in */
	if (sid != NULL)
		CopySid(sizeof(binary_sid), binary_sid, sid);

	/* attempt to lookup the account; this will verify the account is valid and
	 * is will return its sid and the realm that owns it */
	else if(LookupAccountNameW(NULL, user_utf16, binary_sid, &sid_size,
		domain_name, &domain_name_size, &account_type) == 0) {
		errno = ENOENT;
		debug("%s: LookupAccountName() failed: %d.", __FUNCTION__, GetLastError());
		goto cleanup;
	}

	/* convert the binary string to a string */
	if (ConvertSidToStringSidW((PSID) binary_sid, &sid_string) == FALSE) {
		errno = ENOENT;
		goto cleanup;
	}

	/* lookup the account name from the sid */
	WCHAR user_name[UNLEN + 1];
	DWORD user_name_length = ARRAYSIZE(user_name);
	domain_name_size = DNLEN + 1;
	if (LookupAccountSidW(NULL, binary_sid, user_name, &user_name_length,
		domain_name, &domain_name_size, &account_type) == 0) {
		errno = ENOENT;
		debug("%s: LookupAccountSid() failed: %d.", __FUNCTION__, GetLastError());
		goto cleanup;
	}

	/* verify passed account is actually a user account */
	if (account_type != SidTypeUser) {
		errno = ENOENT;
		debug3("%s: Invalid account type: %d.", __FUNCTION__, account_type);
		goto cleanup;
	}

	/* fetch the computer name so we can determine if the specified user is local or not */
	wchar_t computer_name[CNLEN + 1];
	DWORD computer_name_size = ARRAYSIZE(computer_name);
	if (GetComputerNameW(computer_name, &computer_name_size) == 0) {
		goto cleanup;
	}

	/* if standard local user name, just use name without decoration */
	if (_wcsicmp(domain_name, computer_name) == 0) 
		wcscpy_s(user_resolved, ARRAYSIZE(user_resolved), user_name);

	/* put any other format in sam compatible format */
	else
		swprintf_s(user_resolved, ARRAYSIZE(user_resolved), L"%s\\%s", domain_name, user_name);

	/* if one of below fails, set profile path to Windows directory */
	if (swprintf_s(reg_path, PATH_MAX, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%ls", sid_string) == -1 ||
	    RegOpenKeyExW(HKEY_LOCAL_MACHINE, reg_path, 0, STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &reg_key) != 0 ||
	    RegQueryValueExW(reg_key, L"ProfileImagePath", 0, NULL, (LPBYTE)profile_home, &reg_path_len) != 0 ||
	    ExpandEnvironmentStringsW(profile_home, NULL, 0) > PATH_MAX ||
	    ExpandEnvironmentStringsW(profile_home, profile_home_exp, PATH_MAX) == 0)
		if (GetWindowsDirectoryW(profile_home_exp, PATH_MAX) == 0) {
			debug3("GetWindowsDirectoryW failed with %d", GetLastError());
			errno = EOTHER;
			goto cleanup;
		}

	/* convert to utf8, make name lowercase, and assign to output structure*/
	_wcslwr_s(user_resolved, wcslen(user_resolved) + 1);
	if ((pw.pw_name = utf16_to_utf8(user_resolved)) == NULL ||
		(pw.pw_dir = utf16_to_utf8(profile_home_exp)) == NULL || 
		(pw.pw_sid = utf16_to_utf8(sid_string)) == NULL) {
		reset_pw();
		errno = ENOMEM;
		goto cleanup;
	}

	ret = &pw;

cleanup:

	if (sid_string)
		LocalFree(sid_string);
	if (reg_key)
		RegCloseKey(reg_key);

	return ret;
}

struct passwd*
w32_getpwnam(const char *user_utf8)
{
	wchar_t * user_utf16 = utf8_to_utf16(user_utf8);
	if (user_utf16 == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	return get_passwd(user_utf16, NULL);
}

struct passwd*
w32_getpwuid(uid_t uid)
{
	struct passwd* ret = NULL;
	HANDLE token = NULL;
	TOKEN_USER* info = NULL;
	DWORD info_len = 0;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE ||
		GetTokenInformation(token, TokenUser, NULL, 0, &info_len) == TRUE ||
		(info = (TOKEN_USER*)malloc(info_len)) == NULL ||
		GetTokenInformation(token, TokenUser, info, info_len, &info_len) == FALSE)
		goto cleanup;

	ret = get_passwd(NULL, info->User.Sid);

cleanup:

	if (token)
		CloseHandle(token);
	if (info)
		free(info);

	return ret;
}

char *
group_from_gid(gid_t gid, int nogroup)
{
	return "-";
}

char *
user_from_uid(uid_t uid, int nouser)
{
	return "-";
}

uid_t
getuid(void)
{
	return 1;
}

gid_t
getgid(void)
{
	return 0;
}

uid_t
geteuid(void)
{
	return 1;
}

gid_t
getegid(void)
{
	return 0;
}

int
setuid(uid_t uid)
{
	return 0;
}

int
setgid(gid_t gid)
{
	return 0;
}

int
seteuid(uid_t uid)
{
	return 0;
}

int
setegid(gid_t gid)
{
	return 0;
}

void 
endpwent(void)
{
	return;
}
