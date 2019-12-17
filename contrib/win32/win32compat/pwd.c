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
char* shell_command_option = NULL;
BOOLEAN arg_escape = TRUE;

/* returns 0 on success, and -1 with errno set on failure */
static int
set_defaultshell()
{
	HKEY reg_key = 0;
	int tmp_len, ret = -1;
	REGSAM mask = STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_WOW64_64KEY;
	wchar_t path_buf[PATH_MAX], option_buf[32];
	char *pw_shellpath_local = NULL, *command_option_local = NULL;

	errno = 0;

	/* if already set, return success */
	if (pw_shellpath != NULL)
		return 0;

	path_buf[0] = L'\0';
	option_buf[0] = L'\0';

	tmp_len = _countof(path_buf);
	if ((RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\OpenSSH", 0, mask, &reg_key) == ERROR_SUCCESS) &&
	    (RegQueryValueExW(reg_key, L"DefaultShell", 0, NULL, (LPBYTE)path_buf, &tmp_len) == ERROR_SUCCESS) &&
	    (path_buf[0] != L'\0')) {
		/* fetched default shell path from registry */
		tmp_len = _countof(option_buf);
		DWORD size = sizeof(DWORD);
		DWORD escape_option = 1;
		if (RegQueryValueExW(reg_key, L"DefaultShellCommandOption", 0, NULL, (LPBYTE)option_buf, &tmp_len) != ERROR_SUCCESS)
			option_buf[0] = L'\0';
		if (RegQueryValueExW(reg_key, L"DefaultShellEscapeArguments", 0, NULL, (LPBYTE)&escape_option, &size) == ERROR_SUCCESS)
			arg_escape = (escape_option != 0) ? TRUE : FALSE;
	} else {
		if (!GetSystemDirectoryW(path_buf, _countof(path_buf))) {
			errno = GetLastError();
			goto cleanup;
		}
		if (wcscat_s(path_buf, _countof(path_buf), L"\\cmd.exe") != 0)
			goto cleanup;
	}

	if ((pw_shellpath_local = utf16_to_utf8(path_buf)) == NULL)
		goto cleanup;

	if (option_buf[0] != L'\0')
		if ((command_option_local = utf16_to_utf8(option_buf)) == NULL)
			goto cleanup;

	convertToBackslash(pw_shellpath_local);
	to_lower_case(pw_shellpath_local);
	pw_shellpath = pw_shellpath_local;
	pw_shellpath_local = NULL;
	shell_command_option = command_option_local;
	command_option_local = NULL;

	ret = 0;
cleanup:
	if (pw_shellpath_local)
		free(pw_shellpath_local);

	if (command_option_local)
		free(command_option_local);

	return ret;
}


int
initialize_pw()
{
	if (set_defaultshell() != 0)
		return -1;

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

static void 
clean_pw()
{
	if (pw.pw_name)
		free(pw.pw_name);
	if (pw.pw_dir)
		free(pw.pw_dir);
	pw.pw_name = NULL;
	pw.pw_dir = NULL;
}

static int
reset_pw()
{
	if (initialize_pw() != 0)
		return -1;

	clean_pw();

	return 0;
}

static struct passwd*
get_passwd(const wchar_t * user_utf16, PSID sid)
{
	wchar_t user_resolved[DNLEN + 1 + UNLEN + 1];
	struct passwd *ret = NULL;
	wchar_t *sid_string = NULL, *tmp = NULL, *user_utf16_modified = NULL;
	wchar_t reg_path[PATH_MAX], profile_home[PATH_MAX], profile_home_exp[PATH_MAX];
	DWORD reg_path_len = PATH_MAX;
	HKEY reg_key = 0;	
	
	BYTE binary_sid[SECURITY_MAX_SID_SIZE];
	DWORD sid_size = ARRAYSIZE(binary_sid);
	WCHAR domain_name[DNLEN + 1] = L"";
	DWORD domain_name_size = DNLEN + 1;
	SID_NAME_USE account_type = 0;

	errno = 0;
	if (reset_pw() != 0)
		return NULL;
	
	/*
	 * We support both "domain\user" and "domain/user" formats.
	 * But win32 APIs only accept domain\user format so convert it.
	 */
	if (user_utf16) {
		user_utf16_modified = _wcsdup(user_utf16);
		if (!user_utf16_modified) {
			errno = ENOMEM;
			error("%s failed to duplicate %s", __func__, user_utf16);
			goto cleanup;
		}

		if (tmp = wcsstr(user_utf16_modified, L"/"))
			*tmp = L'\\';
	}

	/* skip forward lookup on name if sid was passed in */
	if (sid != NULL)
		CopySid(sizeof(binary_sid), binary_sid, sid);
	/* else attempt to lookup the account; this will verify the account is valid and
	 * is will return its sid and the realm that owns it */
	else if(LookupAccountNameW(NULL, user_utf16_modified, binary_sid, &sid_size,
	    domain_name, &domain_name_size, &account_type) == 0) {
		errno = ENOENT;
		debug("%s: LookupAccountName() failed: %d.", __FUNCTION__, GetLastError());
		goto cleanup;
	}

	/* convert the binary string to a string */
	if (ConvertSidToStringSidW((PSID) binary_sid, &sid_string) == FALSE) {
		errno = errno_from_Win32LastError();
		goto cleanup;
	}

	/* lookup the account name from the sid */
	WCHAR user_name[UNLEN + 1];
	DWORD user_name_length = ARRAYSIZE(user_name);
	domain_name_size = DNLEN + 1;
	if (LookupAccountSidW(NULL, binary_sid, user_name, &user_name_length,
	    domain_name, &domain_name_size, &account_type) == 0) {
		errno = errno_from_Win32LastError();
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

	/* If standard local user name, just use name without decoration */
	if ((_wcsicmp(domain_name, computer_name) == 0) && (_wcsicmp(computer_name, user_name) != 0))
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
	    (pw.pw_dir = utf16_to_utf8(profile_home_exp)) == NULL) {
		clean_pw();
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

static struct passwd*
getpwnam_placeholder(const char* user) {
	wchar_t tmp_home[PATH_MAX];
	char *pw_name = NULL, *pw_dir = NULL;
	struct passwd* ret = NULL;

	if (GetWindowsDirectoryW(tmp_home, PATH_MAX) == 0) {
		debug3("GetWindowsDirectoryW failed with %d", GetLastError());
		errno = EOTHER;
		goto cleanup;
	}
	pw_name = _strdup(user);
	pw_dir = utf16_to_utf8(tmp_home);

	if (!pw_name || !pw_dir) {
		errno = ENOMEM;
		goto cleanup;
	}

	pw.pw_name = pw_name;
	pw_name = NULL;
	pw.pw_dir = pw_dir;
	pw_dir = NULL;

	ret = &pw;
cleanup:
	if (pw_name)
		free(pw_name);
	if (pw_dir)
		free(pw_dir);

	return ret;
}

struct passwd*
w32_getpwnam(const char *user_utf8)
{
	struct passwd* ret = NULL;
	wchar_t * user_utf16 = NULL;

	user_utf16 = utf8_to_utf16(user_utf8);
	if (user_utf16 == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	ret = get_passwd(user_utf16, NULL);
	if (ret != NULL)
		goto done;

	/* for unpriviliged user account, create placeholder and return*/
	if (_stricmp(user_utf8, "sshd") == 0) {
		ret = getpwnam_placeholder(user_utf8);
		goto done;
	}

	/* check if custom passwd auth is enabled */
	if (get_custom_lsa_package())
		ret = getpwnam_placeholder(user_utf8);

done:
	if (user_utf16)
		free(user_utf16);
	return ret;
}

struct passwd*
w32_getpwuid(uid_t uid)
{
	struct passwd* ret = NULL;
	PSID cur_user_sid = NULL;
	
	if ((cur_user_sid = get_sid(NULL)) == NULL)
		goto cleanup;

	ret = get_passwd(NULL, cur_user_sid);

cleanup:
	if (cur_user_sid)
		free(cur_user_sid);

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

struct passwd *getpwent(void)
{
	return NULL;
}

void setpwent(void)
{
	return;
}

void
endpwent(void)
{
	return;
}
