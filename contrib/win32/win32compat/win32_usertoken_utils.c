/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*   Utilities to generate user tokens
*
* Author: Bryan Berns <berns@uwalumni.com>
*   Updated s4u, logon, and profile loading routines to use 
*   normalized login names.
*
* Copyright (c) 2015 Microsoft Corp.
* All rights reserved
*
* Microsoft openssh win32 port
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
#define SECURITY_WIN32
#define UMDF_USING_NTSTATUS 
#include <Windows.h>
#include <UserEnv.h>
#include <Ntsecapi.h>
#include <ntstatus.h>
#include <Shlobj.h>
#include <LM.h>
#include <security.h>

#include "inc\utf.h"
#include "logonuser.h"
#include <Ntsecapi.h>
#include <Strsafe.h>
#include <sddl.h>
#include <ntstatus.h>
#include "misc_internal.h"
#include "lsa_missingdefs.h"
#include "Debug.h"
#include "inc\pwd.h"

#pragma warning(push, 3)

static void
InitLsaString(LSA_STRING *lsa_string, const char *str)
{
	if (!str)
		memset(lsa_string, 0, sizeof(LSA_STRING));
	else {
		lsa_string->Buffer = (char *)str;
		lsa_string->Length = (USHORT)strlen(str);
		lsa_string->MaximumLength = lsa_string->Length + 1;
	}
}

static void
EnablePrivilege(const char *privName, int enabled)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hProcToken = NULL;
	LUID luid;

	int exitCode = 1;

	if (LookupPrivilegeValueA(NULL, privName, &luid) == FALSE ||
		OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hProcToken) == FALSE)
		goto done;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = enabled ? SE_PRIVILEGE_ENABLED : 0;

	AdjustTokenPrivileges(hProcToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

done:
	if (hProcToken)
		CloseHandle(hProcToken);

	return;
}

HANDLE
generate_s4u_user_token(wchar_t* user_cpn, int impersonation) {
	HANDLE lsa_handle = NULL, token = NULL;
	ULONG auth_package_id;
	NTSTATUS ret, subStatus;
	void * logon_info = NULL;
	size_t logon_info_size;
	LSA_STRING logon_process_name, auth_package_name, origin_name;
	TOKEN_SOURCE source_context;
	PKERB_INTERACTIVE_PROFILE profile = NULL;
	LUID logon_id = { 0, 0 };
	QUOTA_LIMITS quotas;
	DWORD profile_size;

	/* the format for the user will be constrained to the output of get_passwd()
	 * so only the only two formats are a NetBiosDomain\SamAccountName which is
	 * a domain account or just SamAccountName in which is a local account */
	BOOL domain_user = wcschr(user_cpn, L'\\') != NULL;
	
	/* initialize connection to local security provider */
	if (impersonation) {

		/* trusted mode - used for impersonation */
		LSA_OPERATIONAL_MODE mode;
		InitLsaString(&logon_process_name, "sshd");
		if ((ret = LsaRegisterLogonProcess(&logon_process_name, &lsa_handle, &mode)) != STATUS_SUCCESS)
			goto done;
	}
	else {
		/* untrusted mode - used for information lookup */
		if (LsaConnectUntrusted(&lsa_handle) != STATUS_SUCCESS)
			goto done;
	}

	InitLsaString(&auth_package_name, (domain_user) ? MICROSOFT_KERBEROS_NAME_A : MSV1_0_PACKAGE_NAME);
	if (ret = LsaLookupAuthenticationPackage(lsa_handle, &auth_package_name, &auth_package_id) != STATUS_SUCCESS)
		goto done;

	if (domain_user) {

		/* lookup the upn for the user */
		WCHAR domain_upn[MAX_UPN_LEN + 1];
		ULONG domain_upn_len = ARRAYSIZE(domain_upn);
		if (TranslateNameW(user_cpn, NameSamCompatible,
			NameUserPrincipal, domain_upn, &domain_upn_len) == 0) {

			/* upn lookup failed so resort to attempting samcompatiblename */
			debug3("%s: Unable to discover upn for user '%s': %d",
				__FUNCTION__, user_cpn, GetLastError());
			wcscpy_s(domain_upn, ARRAYSIZE(domain_upn), user_cpn);
		}

		KERB_S4U_LOGON *s4u_logon;
		logon_info_size = sizeof(KERB_S4U_LOGON);

		/* additional buffer is necessary at end to hold user name */
		logon_info_size += (wcslen(domain_upn) * sizeof(wchar_t));
		logon_info = calloc(1, logon_info_size);
		if (logon_info == NULL)
			goto done;
		s4u_logon = (KERB_S4U_LOGON*)logon_info;
		s4u_logon->MessageType = KerbS4ULogon;
		s4u_logon->Flags = (impersonation) ? 0x0 : 0x8;

		/* copy the user name into the memory immediately after the structure */
		s4u_logon->ClientUpn.Length = (USHORT)wcslen(domain_upn) * sizeof(wchar_t);
		s4u_logon->ClientUpn.MaximumLength = s4u_logon->ClientUpn.Length;
		s4u_logon->ClientUpn.Buffer = (PWSTR)(s4u_logon + 1);
		if (memcpy_s(s4u_logon->ClientUpn.Buffer, s4u_logon->ClientUpn.Length,
			domain_upn, s4u_logon->ClientUpn.Length))
			goto done;
	}
	else {

		MSV1_0_S4U_LOGON *s4u_logon;
		logon_info_size = sizeof(MSV1_0_S4U_LOGON);

		/* additional buffer is necessary at end to hold user and computer name */
		logon_info_size += (wcslen(user_cpn) + wcslen(L".")) * sizeof(wchar_t);
		logon_info = calloc(1, logon_info_size);
		if (logon_info == NULL)
			goto done;
		s4u_logon = (MSV1_0_S4U_LOGON*)logon_info;
		s4u_logon->MessageType = MsV1_0S4ULogon;
		s4u_logon->Flags = 0x0;

		/* copy the user name into the memory immediately after the structure */
		s4u_logon->UserPrincipalName.Length = (USHORT)wcslen(user_cpn) * sizeof(wchar_t);
		s4u_logon->UserPrincipalName.MaximumLength = s4u_logon->UserPrincipalName.Length;
		s4u_logon->UserPrincipalName.Buffer = (WCHAR*)(s4u_logon + 1);
		if (memcpy_s(s4u_logon->UserPrincipalName.Buffer, s4u_logon->UserPrincipalName.Length,
			user_cpn, s4u_logon->UserPrincipalName.Length))
			goto done;

		/* copy the computer name immediately after the user name */
		s4u_logon->DomainName.Length = (USHORT)wcslen(L".") * sizeof(wchar_t);
		s4u_logon->DomainName.MaximumLength = s4u_logon->DomainName.Length;
		s4u_logon->DomainName.Buffer = (PWSTR)(((PBYTE)s4u_logon->UserPrincipalName.Buffer)
			+ s4u_logon->UserPrincipalName.Length);
		if (memcpy_s(s4u_logon->DomainName.Buffer, s4u_logon->DomainName.Length,
			L".", s4u_logon->DomainName.Length))
			goto done;
	}

	if (strcpy_s(source_context.SourceName, TOKEN_SOURCE_LENGTH, "sshd") != 0 ||
		AllocateLocallyUniqueId(&source_context.SourceIdentifier) != TRUE)
		goto done;

	InitLsaString(&origin_name, "sshd");
	if ((ret = LsaLogonUser(lsa_handle, &origin_name, Network, auth_package_id,
		logon_info, (ULONG)logon_info_size, NULL, &source_context,
		(PVOID*)&profile, &profile_size, &logon_id, &token, &quotas, &subStatus)) != STATUS_SUCCESS) {
		debug("%s: LsaLogonUser() failed: %d SubStatus %d.", __FUNCTION__, ret, subStatus);
		goto done;
	}

	debug3("LsaLogonUser Succeeded (Impersonation: %d)", impersonation);

done:
	if (lsa_handle)
		LsaDeregisterLogonProcess(lsa_handle);
	if (logon_info)
		free(logon_info);
	if (profile)
		LsaFreeReturnBuffer(profile);

	return token;
}

HANDLE
process_custom_lsa_auth(const char* user, const char* pwd, const char* lsa_pkg)
{
	HANDLE token = NULL, lsa_handle = NULL;
	LSA_OPERATIONAL_MODE mode;
	ULONG auth_package_id;
	NTSTATUS ret, subStatus;
	LSA_STRING logon_process_name, lsa_auth_package_name, origin_name;
	TOKEN_SOURCE source_context;
	PVOID profile = NULL;
	LUID logon_id = { 0, 0 };
	QUOTA_LIMITS quotas;
	DWORD profile_size;
	int retVal = -1;
	wchar_t *user_utf16 = NULL, *pwd_utf16 = NULL, *seperator = NULL;
	wchar_t logon_info[UNLEN + 1 + PWLEN + 1 + DNLEN + 1];
	ULONG logon_info_size = ARRAYSIZE(logon_info);

	debug3("LSA auth request, user:%s lsa_pkg:%s ", user, lsa_pkg);

	if ((user_utf16 = utf8_to_utf16(user)) == NULL ||
		(pwd_utf16 = utf8_to_utf16(pwd)) == NULL)
		goto done;
	
	/* the format for the user will be constrained to the output of get_passwd()
	* so only the only two formats are NetBiosDomain\SamAccountName which is
	* a domain account or just SamAccountName in which is a local account */

	seperator = wcschr(user_utf16, L'\\');
	if (seperator != NULL) {
		/* domain user: generate login info string user;password;domain */
		swprintf_s(logon_info, ARRAYSIZE(logon_info), L"%s;%s;%.*s",
			seperator + 1, pwd_utf16, (int) (seperator - user_utf16), user_utf16);
	} else {
		/* local user: generate login info string user;password */
		swprintf_s(logon_info, ARRAYSIZE(logon_info), L"%s;%s",
			user_utf16, pwd_utf16);
	}

	InitLsaString(&logon_process_name, "sshd");
	InitLsaString(&lsa_auth_package_name, lsa_pkg);
	InitLsaString(&origin_name, "sshd");

	if ((ret = LsaRegisterLogonProcess(&logon_process_name, &lsa_handle, &mode)) != STATUS_SUCCESS) {
		error("LsaRegisterLogonProcess failed, error:%x", ret);
		goto done;
	}

	if ((ret = LsaLookupAuthenticationPackage(lsa_handle, &lsa_auth_package_name, &auth_package_id)) != STATUS_SUCCESS) {
		error("LsaLookupAuthenticationPackage failed, lsa auth pkg:%ls error:%x", lsa_pkg, ret);
		goto done;
	}

	strcpy_s(source_context.SourceName, sizeof(source_context.SourceName), "sshd");

	if (!AllocateLocallyUniqueId(&source_context.SourceIdentifier)) {
		error("AllocateLocallyUniqueId failed, error:%d", GetLastError());
		goto done;
	}

	if ((ret = LsaLogonUser(lsa_handle, &origin_name, Network, auth_package_id,
		logon_info, (ULONG)logon_info_size, NULL, &source_context,
		(PVOID*)&profile, &profile_size, &logon_id, &token, &quotas, &subStatus)) != STATUS_SUCCESS) {
		debug("%s: LsaLogonUser() failed: %d SubStatus %d.", __FUNCTION__, ret, subStatus);
		goto done;
	}

	debug3("LSA auth request is successful for user:%s ", user);
	retVal = 0;
done:
	if (lsa_handle)
		LsaDeregisterLogonProcess(lsa_handle);
	if (profile)
		LsaFreeReturnBuffer(profile);
	if (user_utf16)
		free(user_utf16);
	if (pwd_utf16) {
		SecureZeroMemory(pwd_utf16, wcslen(pwd_utf16) * sizeof(WCHAR));
		free(pwd_utf16);
	}
	SecureZeroMemory(logon_info, sizeof(logon_info));

	return token;
}

HANDLE generate_sshd_virtual_token();
HANDLE generate_sshd_token_as_nonsystem();

HANDLE
get_user_token(char* user, int impersonation) {
	HANDLE token = NULL;
	wchar_t *user_utf16 = NULL;

	if ((user_utf16 = utf8_to_utf16(user)) == NULL) {
		debug("out of memory");
		goto done;
	}

	if (wcscmp(user_utf16, L"sshd") == 0) {
		/* not running as system, try generating sshd token as admin */
		if (!am_system() && (token = generate_sshd_token_as_nonsystem()) != 0)
			goto done;
			
		if ((token = generate_sshd_virtual_token()) == 0)
  		    error("unable to generate sshd virtual token, ensure sshd service has TCB privileges");

		goto done;
	}

	if (!am_system()) {
		struct passwd* pwd = w32_getpwuid(0);
		if (strcmp(pwd->pw_name, user) == 0)
			OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS_P, &token);
		else
			debug("unable to generate user token for %s as I am not running as system", user);

		goto done;
	}

	if ((token = generate_s4u_user_token(user_utf16, impersonation)) == 0) {
		debug3("unable to generate token for user %ls", user_utf16);
		/* work around for https://github.com/PowerShell/Win32-OpenSSH/issues/727 by doing a fake login */
		LogonUserExExWHelper(L"FakeUser", L"FakeDomain", L"FakePasswd",
			LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, NULL, &token, NULL, NULL, NULL, NULL);
		if ((token = generate_s4u_user_token(user_utf16, impersonation)) == 0) {
			error("unable to generate token on 2nd attempt for user %ls", user_utf16);
			goto done;
		}
	}

done:
	if (user_utf16)
		free(user_utf16);

	return token;
}

int 
load_user_profile(HANDLE user_token, char* user)
{
	wchar_t * user_utf16 = NULL;

	if (!am_system()) {
	    debug("Not running as SYSTEM: skipping loading user profile");
	    return 0;
	}

	if ((user_utf16 = utf8_to_utf16(user)) == NULL) {
		fatal("out of memory");
		return -1;
	}

	/* note: user string will normalized form output of get_passwd() */
	wchar_t * user_name = user_utf16;
	wchar_t * domain_name = NULL;
	wchar_t * seperator = wcschr(user_name, L'\\');
	if (seperator != NULL) {
		domain_name = user_name;
		*seperator = L'\0';
		user_name = seperator + 1;
	}

	PROFILEINFOW profileInfo = { 0 };
	profileInfo.dwSize = sizeof(profileInfo);
	profileInfo.dwFlags = PI_NOUI;
	profileInfo.lpProfilePath = NULL;
	profileInfo.lpUserName = user_name;
	profileInfo.lpDefaultPath = NULL;
	profileInfo.lpServerName = domain_name;
	profileInfo.lpPolicyPath = NULL;
	profileInfo.hProfile = NULL;
	EnablePrivilege("SeBackupPrivilege", 1);
	EnablePrivilege("SeRestorePrivilege", 1);
	if (LoadUserProfileW(user_token, &profileInfo) == FALSE) {
		debug3("%s: LoadUserProfileW() failed for user %S with error %d.", __FUNCTION__, GetLastError());
	}
	EnablePrivilege("SeBackupPrivilege", 0);
	EnablePrivilege("SeRestorePrivilege", 0);

	if (user_utf16)
		free(user_utf16);

	return 0;
}


/* *** virtual account token generation logic ***/

char* LSAMappingErrorDetails[] = {
	"LsaSidNameMappingOperation_Success",
	"LsaSidNameMappingOperation_NonMappingError",
	"LsaSidNameMappingOperation_NameCollision",
	"LsaSidNameMappingOperation_SidCollision",
	"LsaSidNameMappingOperation_DomainNotFound",
	"LsaSidNameMappingOperation_DomainSidPrefixMismatch",
	"LsaSidNameMappingOperation_MappingNotFound"
};

#define VIRTUALUSER_DOMAIN L"VIRTUAL USERS"
#define VIRTUALUSER_GROUP_NAME L"ALL VIRTUAL USERS"

/* returns 0 on success -1 on failure */
int
AddSidMappingToLsa(PUNICODE_STRING domain_name,
	 PUNICODE_STRING account_name,
	 PSID sid)
{
	LSA_SID_NAME_MAPPING_OPERATION_INPUT   input = { 0 };
	PLSA_SID_NAME_MAPPING_OPERATION_OUTPUT p_output = NULL;
	LSA_SID_NAME_MAPPING_OPERATION_ERROR op_result =
		LsaSidNameMappingOperation_NonMappingError;
	NTSTATUS status = STATUS_SUCCESS;
	int ret = 0;

	input.AddInput.DomainName = *domain_name;
	if (account_name)
		input.AddInput.AccountName = *account_name;
	input.AddInput.Sid = sid;

	status = LsaManageSidNameMapping(LsaSidNameMappingOperation_Add,
		&input,
		&p_output);
	if (status != STATUS_SUCCESS) {
		ret = -1;
		if (p_output) {
			op_result = p_output->AddOutput.ErrorCode;
			if (op_result == LsaSidNameMappingOperation_NameCollision || op_result == LsaSidNameMappingOperation_SidCollision)
				ret = 0; /* OK as it failed due to collision */
			else
				error("LsaManageSidNameMapping failed with : %s \n", LSAMappingErrorDetails[op_result]);
		}
		else
			error("LsaManageSidNameMapping failed with ntstatus: %d \n", status);
	}

	/* TODO - Free p_output */
	/*if (p_output)
		LsaFreeMemory(p_output);*/

	return ret;
}


int RemoveVirtualAccountLSAMapping(PUNICODE_STRING domain_name,
	PUNICODE_STRING account_name)
{
	int ret = 0;

	LSA_SID_NAME_MAPPING_OPERATION_INPUT         input = { 0 };
	PLSA_SID_NAME_MAPPING_OPERATION_OUTPUT       p_output = NULL;
	PLSA_SID_NAME_MAPPING_OPERATION_REMOVE_INPUT remove_input = &input.RemoveInput;

	remove_input->DomainName = *domain_name;
	if (account_name)
		remove_input->AccountName = *account_name;
	
	NTSTATUS status = LsaManageSidNameMapping(LsaSidNameMappingOperation_Remove,
		&input,
		&p_output);
	if (status != STATUS_SUCCESS)
		ret = -1;

	/* TODO - Free p_output */
	/*if (p_output)
		LsaFreeMemory(p_output);*/

	return ret;
}

void 
InitUnicodeString(PUNICODE_STRING dest, PWSTR source)
{
	dest->Buffer = source;
	dest->Length = (USHORT)(wcslen(source) * sizeof(wchar_t));
	dest->MaximumLength = dest->Length + 2;
}

HANDLE generate_sshd_token_as_nonsystem()
{
	/*
	 * This logic tries to reset sshd account password and generate sshd token via logon user
	 * however this token cannot be used to spawn child processes in typical interactive 
	 * scenarios, without modifying ACLs on desktop station. 
	 * Since sshd is run in interactive mode primarily for debugging/testing purposes, we are
	 * simply returing the process token (to be used for spawning unprivileged worker)
	 {
	    UUID uuid;
	    RPC_CWSTR rpc_str;
	    USER_INFO_1003 info;
	    HANDLE token = 0;
	    UuidCreate(&uuid);
	    UuidToStringW(&uuid, (RPC_WSTR*)&rpc_str);

	    info.usri1003_password = (LPWSTR)rpc_str;
	    NetUserSetInfo(NULL, L"sshd", 1003, (LPBYTE)&info, NULL);

	    LogonUserW(L"sshd", NULL, (LPCWSTR)rpc_str, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token);
	}
	*/
	HANDLE token = 0;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS_P , &token);
	return token;
}

HANDLE generate_sshd_virtual_token()
{
	SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
	UNICODE_STRING domain, group, account;
	WCHAR va_name[32]; /* enough to accomodate sshd_123457890 */

	PSID sid_domain = NULL, sid_group = NULL, sid_user = NULL;
	HANDLE va_token = 0, va_token_restricted = 0;

	StringCchPrintfW(va_name, 32, L"%s_%d", L"sshd", GetCurrentProcessId());

	InitUnicodeString(&domain, VIRTUALUSER_DOMAIN);
	InitUnicodeString(&group, VIRTUALUSER_GROUP_NAME);
	InitUnicodeString(&account, va_name);

	/* Initialize SIDs */
	/* domain SID - S-1-5-111 */
	if (!(AllocateAndInitializeSid(&nt_authority,
	    1,
	    111,
	    0,
	    0,
	    0,
	    0,
	    0,
	    0,
	    0,
	    &sid_domain)))
		goto cleanup;

	/* group SID - S-1-5-111-0 */
	if (!(AllocateAndInitializeSid(&nt_authority,
	    2,
	    111,
	    0,
	    0,
	    0,
	    0,
	    0,
	    0,
	    0,
	    &sid_group)))
		goto cleanup;

	/* 
	 * account SID 
	 * this is derived from higher RIDs in sshd service account SID to ensure there are no conflicts
	 * S-1-5-80-3847866527-469524349-687026318-516638107-1125189541 (Well Known group: NT SERVICE\sshd)
	 * Ex account SID - S-1-5-111-3847866527-469524349-687026318-516638107-1125189541-123
	 */
	if (!(AllocateAndInitializeSid(&nt_authority,
	    7,
	    111,
	    3847866527,
	    469524349,
	    687026318,
	    516638107,
	    1125189541,
	    GetCurrentProcessId(),
	    0,
	    &sid_user)))
		goto cleanup;

	/* Map the domain SID */
	if (AddSidMappingToLsa(&domain, NULL, sid_domain) != 0)
		goto cleanup;

	/* Map the group SID */
	if (AddSidMappingToLsa(&domain, &group, sid_group) != 0)
		goto cleanup;

	/* Map the user SID */
	if (AddSidMappingToLsa(&domain, &account, sid_user) != 0)
		goto cleanup;

	/* Logon virtual and create token */
	if (!LogonUserExExWHelper(
	    va_name,
	    VIRTUALUSER_DOMAIN,
	    L"",
	    LOGON32_LOGON_INTERACTIVE,
	    LOGON32_PROVIDER_VIRTUAL,
	    NULL,
	    &va_token,
	    NULL,
	    NULL,
	    NULL,
	    NULL)) {
		debug3("LogonUserExExW failed with %d \n", GetLastError());
		goto cleanup;
	}

	/* remove all privileges */
	if (!CreateRestrictedToken(va_token, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &va_token_restricted ))
		debug3("CreateRestrictedToken failed with %d \n", GetLastError());

	CloseHandle(va_token);

cleanup:
	RemoveVirtualAccountLSAMapping(&domain, &account);

	if (sid_domain)
		FreeSid(sid_domain);
	if (sid_user)
		FreeSid(sid_user);
	if (sid_group)
		FreeSid(sid_group);

	return va_token_restricted;
}



#pragma warning(pop)