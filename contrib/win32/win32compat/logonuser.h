/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Compatibility header to give us pwd-like functionality on Win32
* A lot of passwd fields are not applicable in Windows, neither are some API calls based on this structure
* Ideally, usage of this structure needs to be replaced in core SSH code to an ssh_user interface,
* that each platform can extend and implement.
*/

#ifndef LOGONUSER_H
#define LOGONUSER_H

BOOL
LogonUserExExWHelper(wchar_t *, wchar_t *, wchar_t *, DWORD, DWORD, PTOKEN_GROUPS, PHANDLE, PSID *, PVOID *, LPDWORD, PQUOTA_LIMITS);

#endif
