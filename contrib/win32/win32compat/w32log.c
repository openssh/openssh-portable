/*
* Copyright (c) 2016 Microsoft Corp.
* All rights reserved
*
* Implementation of sys log for windows:
* openlog(), closelog, syslog
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
#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#include "inc/sys/stat.h"

#include "inc\syslog.h"
#include "misc_internal.h"
#include "inc\utf.h"
#include "openssh-events.h"

#define MSGBUFSIZ 1024
static int logfd = -1;
static int sftp_server_logfd = -1;
const char* identity = NULL;
int log_facility = 0;

void openlog_etw()
{
	EventRegisterOpenSSH();
}

void
syslog_etw(int priority, const char *format, const char *formatBuffer)
{
	wchar_t *w_identity = NULL, *w_payload = NULL;
	w_identity = utf8_to_utf16(identity);
	w_payload = utf8_to_utf16(formatBuffer);

	if (!w_identity || !w_payload)
		goto done;

	switch (priority) {
	case LOG_CRIT:
		EventWriteCRITICAL_Event(w_identity, w_payload);
		break;
	case LOG_ERR:
		EventWriteERROR_Event(w_identity, w_payload);
		break;
	case LOG_WARNING:
		EventWriteWARNING_Event(w_identity, w_payload);
		break;
	case LOG_INFO:
		EventWriteINFO_Event(w_identity, w_payload);
		break;
	case LOG_DEBUG:
		EventWriteDEBUG_Event(w_identity, w_payload);
		break;
	default:
		break;
	}

done:
	if (w_identity)
		free(w_identity);
	if (w_payload)
		free(w_payload);
}


/*
 * log file location will be - "%programData%\\openssh\\logs\\<module_name>.log"
 */
void
openlog_file()
{	
	if (strcmp(identity, "sftp-server") == 0 && sftp_server_logfd != -1)
		return;

	if (strcmp(identity, "sftp-server") != 0 && logfd != -1)
		return;
	
	wchar_t *logs_dir = L"\\logs\\";
	wchar_t module_path[PATH_MAX] = { 0 }, log_file[PATH_MAX + 12] = { 0 };
	wchar_t* tmp_identity = NULL;

	if (GetModuleFileNameW(NULL, module_path, PATH_MAX) == 0)
		return;

	if (wcsnlen(module_path, PATH_MAX) > PATH_MAX - wcslen(logs_dir))
		return;

	/* split path root and module */
	{
		wchar_t* tail = module_path + wcsnlen(module_path, PATH_MAX);
		while (tail > module_path && *tail != L'\\' && *tail != L'/')
			tail--;
		
		wchar_t ssh_cfg_path[PATH_MAX] = {0 ,};
		wcscat_s(ssh_cfg_path, _countof(ssh_cfg_path), __wprogdata); /* "%programData%" */
		wcscat_s(ssh_cfg_path, _countof(ssh_cfg_path), L"\\ssh"); /* "%programData%\\ssh" */
		if (strcmp(identity, "sftp-server") == 0) {
			tmp_identity = utf8_to_utf16(identity);
			if (!tmp_identity)
				goto cleanup;
		}
		else {
			tmp_identity = malloc(wcslen(tail) * sizeof(wchar_t));
			if (!tmp_identity)
				goto cleanup;
			if (wcsncpy_s(tmp_identity, wcslen(tail), tail + 1, wcslen(tail) - 5) != 0) {
				goto cleanup;
			}		
		}

		if ((wcsncat_s(log_file, PATH_MAX + 12, ssh_cfg_path, wcslen(ssh_cfg_path)) != 0) ||
		    (wcsncat_s(log_file, PATH_MAX + 12, logs_dir, 6) != 0) ||
		    (wcsncat_s(log_file, PATH_MAX + 12, tmp_identity, wcslen(tmp_identity)) != 0) ||
		    (wcsncat_s(log_file, PATH_MAX + 12, L".log", 4) != 0))
			goto cleanup;
	}
	
	int* fd_ptr = &logfd;
	
	if (strcmp(identity, "sftp-server") == 0)
		fd_ptr = &sftp_server_logfd;

	errno_t err = _wsopen_s(fd_ptr, log_file, O_WRONLY | O_CREAT | O_APPEND, SH_DENYNO, S_IREAD | S_IWRITE);

cleanup:
	if (tmp_identity)
		free(tmp_identity);
}

void
syslog_file(int priority, const char *format, const char *formatBuffer)
{
	char msgbufTimestamp[MSGBUFSIZ];
	SYSTEMTIME st;
	int r;
	int msg_fd;
	
	if (strcmp(identity, "sftp-server") == 0)
		msg_fd = sftp_server_logfd;
	else
		msg_fd = logfd;

	if (msg_fd == -1)
		return;

	GetLocalTime(&st);
	r = _snprintf_s(msgbufTimestamp, sizeof(msgbufTimestamp), _TRUNCATE, "%d %04d-%02d-%02d %02d:%02d:%02d.%03d %s\n",
		GetCurrentProcessId(), st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
		st.wMilliseconds, formatBuffer);
	if (r == -1) {
		_write(msg_fd, "_snprintf_s failed.", 20);
		return;
	}
	msgbufTimestamp[strnlen(msgbufTimestamp, MSGBUFSIZ)] = '\0';
	_write(msg_fd, msgbufTimestamp, (unsigned int)strnlen(msgbufTimestamp, MSGBUFSIZ));
}

void
openlog(const char *ident, unsigned int option, int facility)
{
	identity = ident;
	log_facility = facility;
	if (log_facility == LOG_LOCAL0)
		openlog_file();
	else
		openlog_etw();
}

void
syslog(int priority, const char *format, const char *formatBuffer)
{
	if (log_facility == LOG_LOCAL0)
		syslog_file(priority, format, formatBuffer);
	else
		syslog_etw(priority, format, formatBuffer);
}

void
closelog(void)
{
	/*NOOP*/
}
