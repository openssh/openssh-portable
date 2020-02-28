/*
* Author: Yanbing Wang <yawang@microsoft.com>
*
* Support execution of commands on Win32 based operating systems.
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
#include "includes.h"

#include <unistd.h>
#include "xmalloc.h"
#include "packet.h"

#include "channels.h"
#include "hostfile.h"
#include "auth.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "pal_doexec.h"
#include "misc_internal.h"

#ifndef SUBSYSTEM_NONE
#define SUBSYSTEM_NONE				0
#endif
#ifndef SUBSYSTEM_EXT
#define SUBSYSTEM_EXT				1
#endif
#ifndef SUBSYSTEM_INT_SFTP
#define SUBSYSTEM_INT_SFTP			2
#endif
#ifndef SUBSYSTEM_INT_SFTP_ERROR
#define SUBSYSTEM_INT_SFTP_ERROR	3
#endif

/* import */
extern ServerOptions options;
extern struct sshauthopt *auth_opts;
char **
do_setup_env_proxy(struct ssh *, Session *, const char *);

/*
* do_exec* on Windows
* - Read and set user environment variables from registry
* - Build subsystem cmdline path
* - Interactive shell/commands are executed using ssh-shellhost.exe
* - ssh-shellhost.exe implements server-side PTY for Windows
*/
#define UTF8_TO_UTF16_WITH_CLEANUP(o, i) do {	\
	if (o != NULL) free(o);						\
	if ((o = utf8_to_utf16(i)) == NULL)			\
		goto cleanup;							\
} while (0)

#define GOTO_CLEANUP_ON_ERR(exp) do {	\
	if ((exp) != 0)						\
		goto cleanup;					\
} while(0)

/* TODO  - built env var set and pass it along with CreateProcess */
/* set user environment variables from user profile */
static void
setup_session_user_vars(wchar_t* profile_path)
{
	/* retrieve and set env variables. */
	HKEY reg_key = 0;
	wchar_t name[256];
	wchar_t path[PATH_MAX + 1] = { 0, };
	wchar_t *data = NULL, *data_expanded = NULL, *path_value = NULL, *to_apply;
	DWORD type, name_chars = 256, data_chars = 0, data_expanded_chars = 0, required, i = 0;
	LONG ret;

	SetEnvironmentVariableW(L"USERPROFILE", profile_path);

	if (profile_path[0] && profile_path[1] == L':') {
		SetEnvironmentVariableW(L"HOMEPATH", profile_path + 2);
		wchar_t wc = profile_path[2];
		profile_path[2] = L'\0';
		SetEnvironmentVariableW(L"HOMEDRIVE", profile_path);
		profile_path[2] = wc;
	}
	else
		SetEnvironmentVariableW(L"HOMEPATH", profile_path);

	swprintf_s(path, _countof(path), L"%s\\AppData\\Local", profile_path);
	SetEnvironmentVariableW(L"LOCALAPPDATA", path);
	swprintf_s(path, _countof(path), L"%s\\AppData\\Roaming", profile_path);
	SetEnvironmentVariableW(L"APPDATA", path);

	ret = RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_QUERY_VALUE, &reg_key);
	if (ret != ERROR_SUCCESS)
		//error("Error retrieving user environment variables. RegOpenKeyExW returned %d", ret);
		return;
	else while (1) {
		to_apply = NULL;
		required = data_chars * sizeof(wchar_t);
		name_chars = 256;
		ret = RegEnumValueW(reg_key, i++, name, &name_chars, 0, &type, (LPBYTE)data, &required);
		if (ret == ERROR_NO_MORE_ITEMS)
			break;
		else if (ret == ERROR_MORE_DATA || required > data_chars * 2) {
			if (data != NULL)
				free(data);
			data = xmalloc(required);
			data_chars = required / 2;
			i--;
			continue;
		}
		else if (ret != ERROR_SUCCESS)
			break;

		if (type == REG_SZ)
			to_apply = data;
		else if (type == REG_EXPAND_SZ) {
			required = ExpandEnvironmentStringsW(data, data_expanded, data_expanded_chars);
			if (required > data_expanded_chars) {
				if (data_expanded)
					free(data_expanded);
				data_expanded = xmalloc(required * 2);
				data_expanded_chars = required;
				ExpandEnvironmentStringsW(data, data_expanded, data_expanded_chars);
			}
			to_apply = data_expanded;
		}

		if (_wcsicmp(name, L"PATH") == 0) {
			if ((required = GetEnvironmentVariableW(L"PATH", NULL, 0)) != 0) {
				/* "required" includes null term */
				path_value = xmalloc((wcslen(to_apply) + 1 + required) * 2);
				GetEnvironmentVariableW(L"PATH", path_value, required);
				path_value[required - 1] = L';';
				GOTO_CLEANUP_ON_ERR(memcpy_s(path_value + required, (wcslen(to_apply) + 1) * 2, to_apply, (wcslen(to_apply) + 1) * 2));
				to_apply = path_value;
			}

		}
		if (to_apply)
			SetEnvironmentVariableW(name, to_apply);
	}
cleanup:
	if (reg_key)
		RegCloseKey(reg_key);
	if (data)
		free(data);
	if (data_expanded)
		free(data_expanded);
	if (path_value)
		free(path_value);
}

static int
setup_session_env(struct ssh *ssh, Session* s)
{
	int i = 0, ret = -1;
	char *env_name = NULL, *env_value = NULL, *t = NULL, **env = NULL, *path_env_val = NULL;
	char buf[1024] = { 0 };
	wchar_t *env_name_w = NULL, *env_value_w = NULL, *pw_dir_w = NULL, *tmp = NULL, wbuf[1024] = { 0, };
	char *laddr, *c;

	UTF8_TO_UTF16_WITH_CLEANUP(pw_dir_w, s->pw->pw_dir);
	/* skip domain part (if present) while setting USERNAME */
	c = strchr(s->pw->pw_name, '\\');
	UTF8_TO_UTF16_WITH_CLEANUP(tmp, c ? c + 1 : s->pw->pw_name);
	SetEnvironmentVariableW(L"USERNAME", tmp);

	if (!s->is_subsystem) {
		_snprintf(buf, ARRAYSIZE(buf), "%s@%s", s->pw->pw_name, getenv("COMPUTERNAME"));
		UTF8_TO_UTF16_WITH_CLEANUP(tmp, buf);
		/* escape $ characters as $$ to distinguish from special prompt characters */
		for (int i = 0, j = 0; i < wcslen(tmp) && j < ARRAYSIZE(wbuf) - 1; i++) {
			wbuf[j] = tmp[i];
			if (wbuf[j++] == L'$')
				wbuf[j++] = L'$';
		}
		wcscat_s(wbuf, ARRAYSIZE(wbuf), L" $P$G");
		SetEnvironmentVariableW(L"PROMPT", wbuf);
	}

	setup_session_user_vars(pw_dir_w); /* setup user specific env variables */

	env = do_setup_env_proxy(ssh, s, s->pw->pw_shell);
	while (env_name = env[i]) {
		if (t = strstr(env[i++], "=")) {
			/* SKIP, if not applicable on WINDOWS
			PATH is already set.
			MAIL is not applicable.
			*/
			if ((0 == strncmp(env_name, "PATH=", strlen("PATH="))) ||
				(0 == strncmp(env_name, "MAIL=", strlen("MAIL=")))) {
				continue;
			}

			env_value = t + 1;
			*t = '\0';
			UTF8_TO_UTF16_WITH_CLEANUP(env_name_w, env_name);
			UTF8_TO_UTF16_WITH_CLEANUP(env_value_w, env_value);
			SetEnvironmentVariableW(env_name_w, env_value_w);
		}
	}
	ret = 0;

cleanup:
	if (pw_dir_w)
		free(pw_dir_w);
	if (tmp)
		free(tmp);
	if (env_name_w)
		free(env_name_w);
	if (env_value_w)
		free(env_value_w);
	if (env) {
		i = 0;
		while (t = env[i++])
			free(t);
		free(env);
	}
	return ret;
}

int do_exec_windows(struct ssh *ssh, Session *s, const char *command, int pty) {
	int pipein[2], pipeout[2], pipeerr[2], r, ret = -1;
	char *exec_command = NULL, *posix_cmd_input = NULL, *shell = NULL;
	HANDLE job = NULL, process_handle;
	extern char* shell_command_option;
	extern BOOLEAN arg_escape;

	/* Create three pipes for stdin, stdout and stderr */
	if (pipe(pipein) == -1 || pipe(pipeout) == -1 || pipe(pipeerr) == -1)
		goto cleanup;

	set_nonblock(pipein[0]);
	set_nonblock(pipein[1]);
	set_nonblock(pipeout[0]);
	set_nonblock(pipeout[1]);
	set_nonblock(pipeerr[0]);
	set_nonblock(pipeerr[1]);

	fcntl(pipein[1], F_SETFD, FD_CLOEXEC);
	fcntl(pipeout[0], F_SETFD, FD_CLOEXEC);
	fcntl(pipeerr[0], F_SETFD, FD_CLOEXEC);

	/* setup Environment varibles */
	do {
		static int environment_set = 0;

		if (environment_set)
			break;

		if (setup_session_env(ssh, s) != 0)
			goto cleanup;

		environment_set = 1;
	} while (0);
	int in_chroot = get_in_chroot();
	if (!in_chroot)
		chdir(s->pw->pw_dir);

	if (s->is_subsystem >= SUBSYSTEM_INT_SFTP_ERROR) {
		command = "echo This service allows sftp connections only.";
		pty = 0;
	}

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info;
	HANDLE job_dup;
	pid_t pid = -1;
	char * shell_option = NULL;
	int shell_len = 0;
	/*account for the quotes and null*/
	shell_len = strlen(s->pw->pw_shell) + 2 + 1;
	if ((shell = malloc(shell_len)) == NULL) {
		errno = ENOMEM;
		goto cleanup;
	}

	sprintf_s(shell, shell_len, "\"%s\"", s->pw->pw_shell);
	debug3("shell: %s", shell);

	enum sh_type { SH_OTHER, SH_CMD, SH_PS, SH_BASH, SH_CYGWIN, SH_SHELLHOST } shell_type = SH_OTHER;
	/* get shell type */
	if (strstr(s->pw->pw_shell, "system32\\cmd"))
		shell_type = SH_CMD;
	else if (strstr(s->pw->pw_shell, "powershell"))
		shell_type = SH_PS;
	else if (strstr(s->pw->pw_shell, "ssh-shellhost"))
		shell_type = SH_SHELLHOST;
	else if (strstr(s->pw->pw_shell, "\\bash"))
		shell_type = SH_BASH;
	else if (strstr(s->pw->pw_shell, "cygwin"))
		shell_type = SH_CYGWIN;

	if (shell_command_option)
		shell_option = shell_command_option;
	else if (shell_type == SH_CMD)
		shell_option = "/c";
	else
		shell_option = "-c";
	debug3("shell_option: %s", shell_option);

	if (pty) {
		fcntl(s->ptyfd, F_SETFD, FD_CLOEXEC);
		char *pty_cmd = NULL;
		if (command) {
			size_t len = strlen(shell) + 1 + strlen(shell_option) + 1 + strlen(command) + 1;
			pty_cmd = calloc(1, len);

			strcpy_s(pty_cmd, len, shell);
			strcat_s(pty_cmd, len, " ");
			strcat_s(pty_cmd, len, shell_option);
			strcat_s(pty_cmd, len, " ");
			strcat_s(pty_cmd, len, command);
		} else {
			pty_cmd = shell;
		}

		if (exec_command_with_pty(&pid, pty_cmd, pipein[0], pipeout[1], pipeerr[1], s->col, s->row, s->ttyfd) == -1)
			goto cleanup;
		close(s->ttyfd);
		s->ttyfd = -1;
	}
	else {
		posix_spawn_file_actions_t actions;
		char *spawn_argv[4] = { NULL, };
		exec_command = build_exec_command(command);
		debug3("exec_command: %s", exec_command);

		if (shell_type == SH_PS || shell_type == SH_BASH ||
			shell_type == SH_CYGWIN || (shell_type == SH_OTHER) && arg_escape) {
			spawn_argv[0] = shell;

			if (exec_command) {
				spawn_argv[1] = shell_option;
				spawn_argv[2] = exec_command;
			}
		}
		else {
			/*
			 * no escaping needed for cmd and ssh-shellhost, or escaping is disabled
			 * in registry; pass shell, shell option, and quoted command as cmd path
			 * of posix_spawn to avoid escaping
			 */
			int posix_cmd_input_len = strlen(shell) + 1;

			/* account for " around and null */
			if (exec_command) {
				posix_cmd_input_len += strlen(shell_option) + 1;
				posix_cmd_input_len += strlen(exec_command) + 2 + 1;
			}

			if ((posix_cmd_input = malloc(posix_cmd_input_len)) == NULL) {
				errno = ENOMEM;
				goto cleanup;
			}

			if (exec_command) {
				sprintf_s(posix_cmd_input, posix_cmd_input_len, "%s %s \"%s\"",
					shell, shell_option, exec_command);
			} else {
				sprintf_s(posix_cmd_input, posix_cmd_input_len, "%s",
					shell); 
			}

			spawn_argv[0] = posix_cmd_input;
		}
		debug3("arg escape option: %s", arg_escape ? "TRUE":"FALSE");
		debug3("spawn_argv[0]: %s", spawn_argv[0]);

		if (posix_spawn_file_actions_init(&actions) != 0 ||
			posix_spawn_file_actions_adddup2(&actions, pipein[0], STDIN_FILENO) != 0 ||
			posix_spawn_file_actions_adddup2(&actions, pipeout[1], STDOUT_FILENO) != 0 ||
			posix_spawn_file_actions_adddup2(&actions, pipeerr[1], STDERR_FILENO) != 0) {
			errno = EOTHER;
			error("posix_spawn initialization failed");
			goto cleanup;
		}
		if (posix_spawn(&pid, spawn_argv[0], &actions, NULL, spawn_argv, NULL) != 0) {
			errno = EOTHER;
			error("posix_spawn: %s", strerror(errno));
			goto cleanup;
		}
		posix_spawn_file_actions_destroy(&actions);
	}

	memset(&job_info, 0, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
	job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;

	if ((process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)) == NULL) {
		errno = EOTHER;
		error("cannot get process handle: %d", GetLastError());
		goto cleanup;
	}

	/*
	* assign job object to control processes spawned
	* 1. create job object
	* 2. assign child to job object
	* 3. duplicate job handle into child so it would be the last to close it
	*/
	if ((job = CreateJobObjectW(NULL, NULL)) == NULL ||
		!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &job_info, sizeof(job_info)) ||
		!AssignProcessToJobObject(job, process_handle) ||
		!DuplicateHandle(GetCurrentProcess(), job, process_handle, &job_dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		errno = EOTHER;
		error("cannot associate job object: %d", GetLastError());
		TerminateProcess(process_handle, 255);
		CloseHandle(process_handle);
		goto cleanup;
	}
	s->pid = pid;

	/* Close the child sides of the socket pairs. */
	close(pipein[0]);
	close(pipeout[1]);
	close(pipeerr[1]);

	/*
	* Enter the interactive session.  Note: server_loop must be able to
	* handle the case that fdin and fdout are the same.
	*/
	if (pty) {
		/* Set interactive/non-interactive mode */
		ssh_packet_set_interactive(ssh, 1, options.ip_qos_interactive,
			options.ip_qos_bulk);
		session_set_fds(ssh, s, pipein[1], pipeout[0], -1, 1, 1);
	}
	else {
		/* Set interactive/non-interactive mode */
		ssh_packet_set_interactive(ssh, s->display != NULL, options.ip_qos_interactive,
			options.ip_qos_bulk);
		session_set_fds(ssh, s, pipein[1], pipeout[0], pipeerr[0], s->is_subsystem, 0);
	}

	ret = 0;

cleanup:
	if (exec_command)
		free(exec_command);
	if (posix_cmd_input)
		free(posix_cmd_input);
	if (shell)
		free(shell);
	if (job)
		CloseHandle(job);

	return ret;
}

int
do_exec_no_pty(struct ssh *ssh, Session *s, const char *command) {
	return do_exec_windows(ssh, s, command, 0);
}

int
do_exec_pty(struct ssh *ssh, Session *s, const char *command) {
	return do_exec_windows(ssh, s, command, 1);
}