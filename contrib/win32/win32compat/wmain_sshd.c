/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* wmain entry for sshd. 
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

/* disable inclusion of compatability defitnitions in CRT headers */
#define __STDC__ 1
#include <Windows.h>
#include <wchar.h>
#include <Lm.h>
#include <sddl.h>

#include "inc\utf.h"
#include "misc_internal.h"
#include "Debug.h"

int main(int, char **);
extern HANDLE main_thread;

int scm_start_service(DWORD, LPWSTR*);

SERVICE_TABLE_ENTRYW dispatch_table[] =
{
	{ L"sshd", (LPSERVICE_MAIN_FUNCTIONW)scm_start_service },
	{ NULL, NULL }
};
static SERVICE_STATUS_HANDLE service_status_handle;
static SERVICE_STATUS service_status;


static VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
	service_status.dwCurrentState = dwCurrentState;
	service_status.dwWin32ExitCode = dwWin32ExitCode;
	service_status.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
		service_status.dwControlsAccepted = 0;
	else
		service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
		service_status.dwCheckPoint = 0;
	else
		service_status.dwCheckPoint = 1;

	SetServiceStatus(service_status_handle, &service_status);
}

BOOL WINAPI native_sig_handler(DWORD);
static VOID WINAPI service_handler(DWORD dwControl)
{
	switch (dwControl)
	{
	case SERVICE_CONTROL_STOP: {
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 500);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		/* TODO - GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0); doesn't seem to be invoking
		 * signal handler (native_sig_handler) when sshd runs as service
		 * So calling the signal handler directly to interrupt the deamon's main thread
		 * This is being called after reporting SERVICE_STOPPED because main thread does a exit()
		 * as part of handling Crtl+c
		 */
		native_sig_handler(CTRL_C_EVENT);
		return;
	}
	case SERVICE_CONTROL_INTERROGATE:
		break;
	default:
		break;
	}

	ReportSvcStatus(service_status.dwCurrentState, NO_ERROR, 0);
}

#define SSH_HOSTKEY_GEN_CMDLINE L"ssh-keygen -A"
static void
generate_host_keys()
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	wchar_t cmdline[PATH_MAX];

	if (am_system()) {
		/* create host keys if they dont already exist */
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(STARTUPINFOW);
		ZeroMemory(&pi, sizeof(pi));
		memcpy(cmdline, SSH_HOSTKEY_GEN_CMDLINE, wcslen(SSH_HOSTKEY_GEN_CMDLINE) * 2 + 2);
		if (CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
			WaitForSingleObject(pi.hProcess, INFINITE);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
		}
	}
}

/*
* 1) Create %programdata%\ssh - Administrator group(F), system(F), authorized users(RX).
* 2) Create %programdata%\ssh\logs - Administrator group(F), system(F)
* 3) copy <binary_location>\sshd_config_default to %programdata%\ssh\sshd_config
*/
static void
create_prgdata_ssh_folder()
{
	/* create ssh cfg folder */
	wchar_t ssh_cfg_dir[PATH_MAX] = { 0, };
	wcscpy_s(ssh_cfg_dir, _countof(ssh_cfg_dir), __wprogdata);
	wcscat_s(ssh_cfg_dir, _countof(ssh_cfg_dir), L"\\ssh");
	if (create_directory_withsddl(ssh_cfg_dir, L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)") < 0) {
		printf("failed to create %s", ssh_cfg_dir);
		exit(255);
	}

	/* create logs folder */
	wchar_t logs_dir[PATH_MAX] = { 0, };
	wcscat_s(logs_dir, _countof(logs_dir), ssh_cfg_dir);
	wcscat_s(logs_dir, _countof(logs_dir), L"\\logs");
	if (create_directory_withsddl(logs_dir, L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)") < 0) {
		printf("failed to create %s", logs_dir);
		exit(255);
	}

	/* copy sshd_config_default to %programData%\ssh\sshd_config */
	wchar_t sshd_config_path[PATH_MAX] = { 0, };
	wcscat_s(sshd_config_path, _countof(sshd_config_path), ssh_cfg_dir);
	wcscat_s(sshd_config_path, _countof(sshd_config_path), L"\\sshd_config");
	if (GetFileAttributesW(sshd_config_path) == INVALID_FILE_ATTRIBUTES) {
		wchar_t sshd_config_default_path[PATH_MAX] = { 0, };
		swprintf_s(sshd_config_default_path, PATH_MAX, L"%S\\%s", __progdir, L"sshd_config_default");

		if (CopyFileW(sshd_config_default_path, sshd_config_path, TRUE) == 0) {
			printf("Failed to copy %s to %s, error:%d", sshd_config_default_path, sshd_config_path, GetLastError());
			exit(255);
		}
	}
}

/* Create HKLM\Software\OpenSSH windows registry key */
static void
create_openssh_registry_key()
{
	HKEY ssh_registry_root = NULL;
	wchar_t* sddl_str;
	SECURITY_ATTRIBUTES sa;
	int r;

	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(sa);

	// SDDL - FullAcess to System and Builtin/Admins and read only access to Authenticated users
	sddl_str = L"D:PAI(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;OICI;KR;;;AU)";
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl_str, SDDL_REVISION_1, &sa.lpSecurityDescriptor, &sa.nLength)) {
		printf("cannot convert sddl ERROR:%d", GetLastError());
		return;
	}

	if ((r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, SSH_REGISTRY_ROOT, 0, 0, 0, KEY_WRITE, &sa, &ssh_registry_root, 0)) == ERROR_SUCCESS)
		RegCloseKey(ssh_registry_root);
	else
		printf("cannot create ssh root reg key, ERROR:%d", r);
}

static void
prereq_setup()
{
	create_prgdata_ssh_folder();
	generate_host_keys();
	create_openssh_registry_key();
}

int sshd_main(int argc, wchar_t **wargv) {
	char** argv = NULL;
	int i, r;
	_set_invalid_parameter_handler(invalid_parameter_handler);

	if (argc) {
		if ((argv = malloc(argc * sizeof(char*))) == NULL) {
			printf("out of memory");
			exit(255);
		}

		for (i = 0; i < argc; i++)
			argv[i] = utf16_to_utf8(wargv[i]);
	}

	w32posix_initialize();

	r = main(argc, argv);
	w32posix_done();
	return r;
}

int argc_original = 0;
wchar_t **wargv_original = NULL;

int wmain(int argc, wchar_t **wargv) {
	wchar_t *path_value = NULL, *path_new_value;
	errno_t result = 0;
	size_t path_new_len = 0, len;
	argc_original = argc;
	wargv_original = wargv;

	init_prog_paths();
	/* change current directory to sshd.exe root */
	_wchdir(__wprogdir);

	/*
	* we want to launch scp and sftp executables from the binary directory
	* that sshd is hosted in. This will facilitate hosting and evaluating
	* multiple versions of OpenSSH at the same time.
	* it does not work well for powershell, cygwin, etc if program path is
	* prepended to executable directory. 
	* To achive above, PATH is set to process environment
	*/
	_wdupenv_s(&path_value, &len, L"PATH");
	if (!path_value || (wcsstr(path_value, __wprogdir)) == NULL) {
		path_new_len = wcslen(__wprogdir) + wcslen(path_value) + 2;
		if ((path_new_value = (wchar_t *) malloc(path_new_len * sizeof(wchar_t))) == NULL) {
			errno = ENOMEM;
			error("failed to allocation memory");
			return -1;
		}
		swprintf_s(path_new_value, path_new_len, L"%s%s%s", __wprogdir, path_value ? L";" : L"",  path_value);
		if (result = _wputenv_s(L"PATH", path_new_value)) {
			error("failed to set PATH environment variable: to value:%s, error:%d", path_new_value, result);
			errno = result;
			if (path_new_value)
				free(path_new_value);
			if(path_value)
				free(path_value);
			return -1;
		}
		if (path_new_value)
			free(path_new_value);
		if(path_value)
			free(path_value);
	}

	if (!StartServiceCtrlDispatcherW(dispatch_table)) {
		if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
			return sshd_main(argc, wargv); /* sshd running NOT as service*/
		else
			return -1;
	}

	return 0;
}

int scm_start_service(DWORD num, LPWSTR* args) {
	service_status_handle = RegisterServiceCtrlHandlerW(L"sshd", service_handler);
	ZeroMemory(&service_status, sizeof(service_status));
	service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 300);
	prereq_setup();
	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
	return sshd_main(argc_original, wargv_original);
}
