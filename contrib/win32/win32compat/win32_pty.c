/*
* Author: Balu G <bagajjal@microsoft.com>
*
* This file contains the conpty related functions.
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
#include <stdlib.h>
#include <string.h>
#include "Debug.h"
#include "inc\fcntl.h"
#include "inc\utf.h"
#include "misc_internal.h"
#include "signal_internal.h"

int
is_conpty_supported()
{
	wchar_t *kernel32_dll_path = L"kernel32.dll";
	HMODULE hm_kernel32 = NULL;
	static int isConpty = -1;

	if (isConpty != -1)
		return isConpty;

	isConpty = 0;
	if ((hm_kernel32 = LoadLibraryExW(kernel32_dll_path, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32)) == NULL) {
		error("failed to load %S dll", kernel32_dll_path);
		goto done;
	}

	if (GetProcAddress(hm_kernel32, "CreatePseudoConsole") == NULL) {
		debug3("couldn't find CreatePseudoConsole() in %S dll", kernel32_dll_path);
		goto done;
	}

	isConpty = 1;
	debug3("This windows OS supports conpty");
done:
	if (!isConpty)
		debug3("This windows OS doesn't support conpty");

	return isConpty;
}

int exec_command_with_pty(int * pid, char* cmd, int in, int out, int err, unsigned int col, unsigned int row, int ttyfd)
{
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	wchar_t pty_cmdline[MAX_CMD_LEN] = { 0, };
	int ret = -1;
	HANDLE ttyh = (HANDLE)w32_fd_to_handle(ttyfd);
	wchar_t * cmd_w = NULL;
	unsigned long flags = 0;

	if ((cmd_w = utf8_to_utf16(cmd)) == NULL) {
		errno = ENOMEM;
		return ret;
	}

	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESIZE | STARTF_USECOUNTCHARS;
	si.hStdInput = (HANDLE)w32_fd_to_handle(in);
	si.hStdOutput = (HANDLE)w32_fd_to_handle(out);
	si.lpDesktop = NULL;

	if (is_conpty_supported()) {
		wchar_t system32_path[PATH_MAX] = { 0, };
		SetHandleInformation(ttyh, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
		wchar_t *cmd_fmt = L"%ls\\conhost.exe --headless --width %d --height %d --signal 0x%x -- %ls";

		if (!GetSystemDirectoryW(system32_path, PATH_MAX))
			fatal("unable to retrieve system32 path");

		_snwprintf_s(pty_cmdline,
			MAX_CMD_LEN,
			MAX_CMD_LEN,
			cmd_fmt,
			system32_path,
			col,
			row,
			ttyh,
			cmd_w);

		si.hStdError = si.hStdOutput;
		/* process CTRL+C input. Child processes will inherit this behavior. */
		SetConsoleCtrlHandler(NULL, FALSE);
	}
	else {
		/* launch via  "ssh-shellhost" -p command*/
		_snwprintf_s(pty_cmdline, MAX_CMD_LEN, MAX_CMD_LEN, L"\"%ls\\ssh-shellhost.exe\" ---pty %ls", __wprogdir, cmd_w);
		si.dwXCountChars = col;
		si.dwYCountChars = row;

		/*
		 * In PTY mode, ssh-shellhost takes stderr as control channel
		 * TODO - fix this and pass control channel pipe as a command line parameter
		 */
		si.hStdError = ttyh;
	}

	flags = CREATE_NO_WINDOW;
	debug3("pty commandline: %ls", pty_cmdline);
	if (CreateProcessW(NULL, pty_cmdline, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi)) {
		if (register_child(pi.hProcess, pi.dwProcessId) == -1) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			goto done;
		}
		CloseHandle(pi.hThread);
	}
	else {
		debug("%s - failed to execute %ls, error:%d", __func__, pty_cmdline, GetLastError());
		errno = EOTHER;
		goto done;
	}
	*pid = pi.dwProcessId;
	ret = 0;

done:
	/* disable Ctrl+C hander in this process*/
	SetConsoleCtrlHandler(NULL, TRUE);
	if (cmd_w)
		free(cmd_w);
	return ret;
}