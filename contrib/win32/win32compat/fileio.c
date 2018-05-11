/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Author: Bryan Berns <berns@uwalumni.com>
*  Added symlink support
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

#include <fcntl.h>
#include "inc/sys/stat.h"
#include "inc/sys/types.h"
#include <io.h>
#include <errno.h>
#include <stddef.h>
#include <direct.h>

#include "w32fd.h"
#include "inc\utf.h"
#include "inc\fcntl.h"
#include "inc\pwd.h"
#include "misc_internal.h"
#include "debug.h"
#include <Sddl.h>

/* internal read buffer size */
#define READ_BUFFER_SIZE 100*1024
/* internal write buffer size */
#define WRITE_BUFFER_SIZE 100*1024

/*
* A ACE is a binary data structure of changeable length
* https://msdn.microsoft.com/en-us/library/windows/desktop/aa374928(v=vs.85).aspx
* The value is calculated based on current need: max sid string (184) plus the enough spaces for other fields in ACEs
*/
#define MAX_ACE_LENGTH 225
/* 
* A security descriptor is a binary data structure of changeable length
* https://msdn.microsoft.com/en-us/library/windows/desktop/aa379570(v=vs.85).aspx
* The value is calculated based on current need: 4 ACEs plus the enough spaces for owner sid and dcal flag
*/
#define SDDL_LENGTH 5* MAX_ACE_LENGTH

/*MAX length attribute string looks like 0xffffffff*/
#define MAX_ATTRIBUTE_LENGTH 10

#define errno_from_Win32LastError() errno_from_Win32Error(GetLastError())

struct createFile_flags {
	DWORD dwDesiredAccess;
	DWORD dwShareMode;
	SECURITY_ATTRIBUTES securityAttributes;
	DWORD dwCreationDisposition;
	DWORD dwFlagsAndAttributes;
};

int syncio_initiate_read(struct w32_io* pio);
int syncio_initiate_write(struct w32_io* pio, DWORD num_bytes);
int syncio_close(struct w32_io* pio);

/* maps Win32 error to errno */
int
errno_from_Win32Error(int win32_error)
{
	switch (win32_error) {
	case ERROR_PRIVILEGE_NOT_HELD:
	case ERROR_ACCESS_DENIED:
		return EACCES;
	case ERROR_OUTOFMEMORY:
		return ENOMEM;
	case ERROR_FILE_EXISTS:
		return EEXIST;
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
	case ERROR_INVALID_NAME:
		return ENOENT;
	default:
		return win32_error;
	}
}

struct w32_io*
fileio_afunix_socket() 
{
	struct w32_io* ret = (struct w32_io*)malloc(sizeof(struct w32_io));
	if (ret == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	memset(ret, 0, sizeof(struct w32_io));
	return ret;
}

int
fileio_connect(struct w32_io* pio, char* name) 
{
	wchar_t* name_w = NULL;
	HANDLE h = INVALID_HANDLE_VALUE;
	int ret = 0;

	if (pio->handle != 0 && pio->handle != INVALID_HANDLE_VALUE) {
		debug3("fileio_connect called in unexpected state, pio = %p", pio);
		errno = EOTHER;
		ret = -1;
		goto cleanup;
	}

	if ((name_w = utf8_to_utf16(name)) == NULL) {
		errno = ENOMEM;
		return -1;
	}
	
	do {
		h = CreateFileW(name_w, GENERIC_READ | GENERIC_WRITE, 0,
			NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
	
		if (h != INVALID_HANDLE_VALUE)
			break;
		if (GetLastError() != ERROR_PIPE_BUSY)
			break;
	
		debug4("waiting for agent connection, retrying after 1 sec");
		if ((ret = wait_for_any_event(NULL, 0, 1000) != 0) != 0)
			goto cleanup;
	} while(1);

	if (h == INVALID_HANDLE_VALUE) {
		debug3("unable to connect to pipe %ls, error: %d", name_w, GetLastError());
		errno = errno_from_Win32LastError();
		ret = -1;
		goto cleanup;
	}

	if (SetHandleInformation(h, HANDLE_FLAG_INHERIT,
	    pio->fd_flags & FD_CLOEXEC ? 0 : HANDLE_FLAG_INHERIT) == FALSE) {
		errno = errno_from_Win32LastError();
		debug3("SetHandleInformation failed, error = %d, pio = %p", GetLastError(), pio);
		ret = -1;
		goto cleanup;
	}
	
	pio->handle = h;
	h = INVALID_HANDLE_VALUE;

cleanup:
	if (name_w)
		free(name_w);
	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);
	return ret;
}

/* used to name named pipes used to implement pipe() */
static int pipe_counter = 0;

/*
 * pipe() (unidirectional) and socketpair() (duplex)
 * implementation. Creates an inbound named pipe, uses CreateFile to connect
 * to it. These handles are associated with read end and write end of the pipe
 */
int
fileio_pipe(struct w32_io* pio[2], int duplex)
{
	HANDLE read_handle = INVALID_HANDLE_VALUE, write_handle = INVALID_HANDLE_VALUE;
	struct w32_io *pio_read = NULL, *pio_write = NULL;
	char pipe_name[PATH_MAX];
	SECURITY_ATTRIBUTES sec_attributes;

	if (pio == NULL) {
		errno = EINVAL;
		debug3("pipe - ERROR invalid parameter");
		return -1;
	}

	/* create name for named pipe */
	if (-1 == sprintf_s(pipe_name, PATH_MAX, "\\\\.\\Pipe\\W32PosixPipe.%08x.%08x",
		GetCurrentProcessId(), pipe_counter++)) {
		errno = EOTHER;
		debug3("pipe - ERROR sprintf_s %d", errno);
		goto error;
	}

	sec_attributes.bInheritHandle = TRUE;
	sec_attributes.lpSecurityDescriptor = NULL;
	sec_attributes.nLength = 0;

	/* create named pipe */
	write_handle = CreateNamedPipeA(pipe_name,
		(duplex ? PIPE_ACCESS_DUPLEX : PIPE_ACCESS_OUTBOUND ) | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_WAIT,
		1,
		4096,
		4096,
		0,
		&sec_attributes);
	if (write_handle == INVALID_HANDLE_VALUE) {
		errno = errno_from_Win32LastError();
		debug3("pipe - CreateNamedPipe() ERROR:%d", errno);
		goto error;
	}

	/* connect to named pipe */
	read_handle = CreateFileA(pipe_name,
		duplex ? GENERIC_READ | GENERIC_WRITE :  GENERIC_READ,
		0,
		&sec_attributes,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);
	if (read_handle == INVALID_HANDLE_VALUE) {
		errno = errno_from_Win32LastError();
		debug3("pipe - ERROR CreateFile() :%d", errno);
		goto error;
	}

	/* create w32_io objects encapsulating above handles */
	pio_read = (struct w32_io*)malloc(sizeof(struct w32_io));
	pio_write = (struct w32_io*)malloc(sizeof(struct w32_io));

	if (!pio_read || !pio_write) {
		errno = ENOMEM;
		debug3("pip - ERROR:%d", errno);
		goto error;
	}

	memset(pio_read, 0, sizeof(struct w32_io));
	memset(pio_write, 0, sizeof(struct w32_io));

	pio_read->handle = read_handle;
	pio_write->handle = write_handle;

	pio[0] = pio_read;
	pio[1] = pio_write;
	return 0;

error:
	if (read_handle)
		CloseHandle(read_handle);
	if (write_handle)
		CloseHandle(write_handle);
	if (pio_read)
		free(pio_read);
	if (pio_write)
		free(pio_write);
	return -1;
}

static int
st_mode_to_file_att(int mode, wchar_t * attributes)
{
	DWORD att = 0;
	switch (mode) {
	case S_IRWXO:
		swprintf_s(attributes, MAX_ATTRIBUTE_LENGTH, L"FA");
		break;
	default:
		if((mode & S_IROTH) != 0)
			att |= (FILE_GENERIC_READ | FILE_EXECUTE);
		if ((mode & S_IWOTH) != 0)
			att |= (FILE_GENERIC_WRITE | DELETE);
		if ((mode & S_IXOTH) != 0)
			att |= FILE_GENERIC_EXECUTE;
		swprintf_s(attributes, MAX_ATTRIBUTE_LENGTH, L"%#lx", att);
		break;		
	}
	return 0;
}

/* maps open() file modes and flags to ones needed by CreateFile */
static int
createFile_flags_setup(int flags, mode_t mode, struct createFile_flags* cf_flags)
{
	/* check flags */
	int rwflags = flags & 0x3, c_s_flags = flags & 0xfffffffc, ret = -1;
	PSECURITY_DESCRIPTOR pSD = NULL;
	wchar_t sddl[SDDL_LENGTH + 1] = { 0 }, owner_ace[MAX_ACE_LENGTH + 1] = {0}, everyone_ace[MAX_ACE_LENGTH + 1] = {0};
	wchar_t owner_access[MAX_ATTRIBUTE_LENGTH + 1] = {0}, everyone_access[MAX_ATTRIBUTE_LENGTH + 1] = {0}, *sid_utf16 = NULL;
	PACL dacl = NULL;
	struct passwd * pwd;
	PSID owner_sid = NULL;

	/*
	* should be one of one of the following access modes:
	* O_RDONLY, O_WRONLY, or O_RDWR
	*/
	if ((rwflags != O_RDONLY) && (rwflags != O_WRONLY) && (rwflags != O_RDWR)) {
		debug3("open - flags ERROR: wrong rw flags: %d", flags);
		errno = EINVAL;
		return -1;
	}

	/*only following create and status flags currently supported*/
	if (c_s_flags & ~(O_NONBLOCK | O_APPEND | O_CREAT | O_TRUNC | O_EXCL | O_BINARY)) {
		debug3("open - ERROR: Unsupported flags: %d", flags);
		errno = ENOTSUP;
		return -1;
	}

	cf_flags->dwShareMode = 0;

	switch (rwflags) {
	case O_RDONLY:
		cf_flags->dwDesiredAccess = GENERIC_READ;
		/* refer to https://msdn.microsoft.com/en-us/library/windows/desktop/aa363874(v=vs.85).aspx */
		cf_flags->dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
		break;
	case O_WRONLY:
		cf_flags->dwDesiredAccess = GENERIC_WRITE;
		break;
	case O_RDWR:
		cf_flags->dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
		break;
	}	
	cf_flags->dwCreationDisposition = OPEN_EXISTING;
	if (c_s_flags & O_TRUNC)
		cf_flags->dwCreationDisposition = TRUNCATE_EXISTING;
	if (c_s_flags & O_CREAT) {
		if (c_s_flags & O_EXCL)
			cf_flags->dwCreationDisposition = CREATE_NEW;
		else if (c_s_flags & O_TRUNC)
			cf_flags->dwCreationDisposition = CREATE_ALWAYS;
		else
			cf_flags->dwCreationDisposition = OPEN_ALWAYS;
	}

	if (c_s_flags & O_APPEND)
		cf_flags->dwDesiredAccess = FILE_APPEND_DATA;

	cf_flags->dwFlagsAndAttributes = FILE_FLAG_OVERLAPPED | FILE_FLAG_BACKUP_SEMANTICS;

	// If the mode is USHRT_MAX then we will inherit the permissions from the parent folder.
	if (mode != USHRT_MAX) {
		/*validate mode*/
		/*
		 * __S_IFDIR  __S_IFREG are added for compat
		 * TODO- open(__S_IFDIR) on a file and vice versa should fail
		*/
		if (mode & ~(S_IRWXU | S_IRWXG | S_IRWXO | __S_IFDIR | __S_IFREG)) {
			debug3("open - ERROR: unsupported mode: %d", mode);
			errno = ENOTSUP;
			return -1;
		}

		if ((pwd = getpwuid(0)) == NULL)
			fatal("getpwuid failed.");

		if ((sid_utf16 = utf8_to_utf16(pwd->pw_sid)) == NULL) {
			debug3("Failed to get utf16 of the sid string");
			errno = ENOMEM;
			goto cleanup;
		}

		if (ConvertStringSidToSid(pwd->pw_sid, &owner_sid) == FALSE ||
			(IsValidSid(owner_sid) == FALSE)) {
			debug3("cannot retrieve SID of user %s", pwd->pw_name);
			goto cleanup;
		}

		if (!IsWellKnownSid(owner_sid, WinLocalSystemSid) && ((mode & S_IRWXU) != 0)) {
			if (st_mode_to_file_att((mode & S_IRWXU) >> 6, owner_access) != 0) {
				debug3("st_mode_to_file_att()");
				goto cleanup;
			}
			swprintf_s(owner_ace, MAX_ACE_LENGTH, L"(A;;%s;;;%s)", owner_access, sid_utf16);
		}

		if (mode & S_IRWXO) {
			if (st_mode_to_file_att(mode & S_IRWXO, everyone_access) != 0) {
				debug3("st_mode_to_file_att()");
				goto cleanup;
			}
			swprintf_s(everyone_ace, MAX_ACE_LENGTH, L"(A;;%s;;;WD)", everyone_access);
		}

		swprintf_s(sddl, SDDL_LENGTH, L"O:%sD:PAI(A;;FA;;;BA)(A;;FA;;;SY)%s%s", sid_utf16, owner_ace, everyone_ace);
		if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION, &pSD, NULL) == FALSE) {
			debug3("ConvertStringSecurityDescriptorToSecurityDescriptorW failed with error code %d", GetLastError());
			goto cleanup;
		}

		if (IsValidSecurityDescriptor(pSD) == FALSE) {
			debug3("IsValidSecurityDescriptor return FALSE");
			goto cleanup;
		}
	}

	cf_flags->securityAttributes.lpSecurityDescriptor = pSD;
	cf_flags->securityAttributes.bInheritHandle = TRUE;
	cf_flags->securityAttributes.nLength = sizeof(cf_flags->securityAttributes);

	ret = 0;
cleanup:
	if (owner_sid)
		LocalFree(owner_sid);
	if (sid_utf16)
		free(sid_utf16);
	return ret;
}

/* returns 1 if true, 0 otherwise */
int
file_in_chroot_jail(HANDLE handle, const char* path_utf8) {
	/* ensure final path is within chroot */
	wchar_t path_buf[MAX_PATH], *final_path;
	if (GetFinalPathNameByHandleW(handle, path_buf, MAX_PATH, 0) == 0) {
		debug3("failed to get final path of file:%s error:%d", path_utf8, GetLastError());
		return 0;
	}
	final_path = path_buf + 4;
	to_wlower_case(final_path);
	if ((wcslen(final_path) < wcslen(chroot_pathw)) ||
		memcmp(final_path, chroot_pathw, 2 * wcslen(chroot_pathw)) != 0 ||
		final_path[wcslen(chroot_pathw)] != '\\') {
		debug3("access denied due to attempt to escape chroot jail");
		return 0;
	}

	return 1;
}

/* open() implementation. Uses CreateFile to open file, console, device, etc */
struct w32_io*
fileio_open(const char *path_utf8, int flags, mode_t mode)
{
	struct w32_io* pio = NULL;
	struct createFile_flags cf_flags;
	HANDLE handle = INVALID_HANDLE_VALUE;
	wchar_t *path_utf16 = NULL;
	int nonfs_dev = 0; /* opening a non file system device */

	debug4("open - pathname:%s, flags:%d, mode:%d", path_utf8, flags, mode);
	/* check input params*/
	if (path_utf8 == NULL) {
		errno = EINVAL;
		debug3("open - ERROR:%d", errno);
		return NULL;
	}

	/* if opening null device, point to Windows equivalent */
	if (strncmp(path_utf8, NULL_DEVICE, sizeof(NULL_DEVICE)) == 0) {
		nonfs_dev = 1;
		path_utf16 = utf8_to_utf16(NULL_DEVICE_WIN);
	}
	else
		path_utf16 = resolved_path_utf16(path_utf8);

	if (path_utf16 == NULL) 
		return NULL;

	if (createFile_flags_setup(flags, mode, &cf_flags) == -1) {
		debug3("createFile_flags_setup() failed.");
		goto cleanup;
	}	

	handle = CreateFileW(path_utf16, cf_flags.dwDesiredAccess, cf_flags.dwShareMode,
		&cf_flags.securityAttributes, cf_flags.dwCreationDisposition,
		cf_flags.dwFlagsAndAttributes, NULL);	

	if (handle == INVALID_HANDLE_VALUE) {
		errno = errno_from_Win32LastError();
		debug3("failed to open file:%s error:%d", path_utf8, GetLastError());
		goto cleanup;
	}

	if (chroot_pathw && !nonfs_dev && !file_in_chroot_jail(handle, path_utf8)) {		
		errno = EACCES;
		goto cleanup;
	}
	
	pio = (struct w32_io*)malloc(sizeof(struct w32_io));
	if (pio == NULL) {
		CloseHandle(handle);
		errno = ENOMEM;
		debug3("fileio_open(), failed to allocate memory error:%d", errno);
		goto cleanup;
	}

	memset(pio, 0, sizeof(struct w32_io));

	if (flags & O_NONBLOCK)
		pio->fd_status_flags = O_NONBLOCK;

	pio->handle = handle;
	handle = INVALID_HANDLE_VALUE;

cleanup:
	if ((&cf_flags.securityAttributes != NULL) && (&cf_flags.securityAttributes.lpSecurityDescriptor != NULL))
		LocalFree(cf_flags.securityAttributes.lpSecurityDescriptor);
	if(path_utf16)
		free(path_utf16);
	if (handle != INVALID_HANDLE_VALUE)
		CloseHandle(handle);

	return pio;
}

VOID CALLBACK 
ReadCompletionRoutine(_In_ DWORD dwErrorCode, _In_ DWORD dwNumberOfBytesTransfered, _Inout_ LPOVERLAPPED lpOverlapped)
{
	struct w32_io* pio = (struct w32_io*)((char*)lpOverlapped - offsetof(struct w32_io, read_overlapped));
	debug4("ReadCB pio:%p, pending_state:%d, error:%d, received:%d",
		pio, pio->read_details.pending, dwErrorCode, dwNumberOfBytesTransfered);
	pio->read_details.error = dwErrorCode;
	pio->read_details.remaining = dwNumberOfBytesTransfered;
	pio->read_details.completed = 0;
	pio->read_details.pending = FALSE;
	*((__int64*)&lpOverlapped->Offset) += dwNumberOfBytesTransfered;
}

/* initiate an async read */
/* TODO:  make this a void func, store error in context */
int
fileio_ReadFileEx(struct w32_io* pio, unsigned int bytes_requested)
{
	debug4("ReadFileEx io:%p", pio);

	if (pio->read_details.buf == NULL) {
		pio->read_details.buf = malloc(READ_BUFFER_SIZE);
		if (!pio->read_details.buf) {
			errno = ENOMEM;
			debug4("ReadFileEx - ERROR: %d, io:%p", errno, pio);
			return -1;
		}
	}

	if (FILETYPE(pio) == FILE_TYPE_DISK)
		pio->read_details.buf_size = min(bytes_requested, READ_BUFFER_SIZE);
	else
		pio->read_details.buf_size = READ_BUFFER_SIZE;

	if (ReadFileEx(WINHANDLE(pio), pio->read_details.buf, pio->read_details.buf_size,
		&pio->read_overlapped, &ReadCompletionRoutine))
		pio->read_details.pending = TRUE;
	else {
		errno = errno_from_Win32LastError();
		debug3("ReadFileEx() ERROR:%d, io:%p", GetLastError(), pio);
		return -1;
	}

	return 0;
}

/* read() implementation */
int
fileio_read(struct w32_io* pio, void *dst, size_t max_bytes)
{
	int bytes_copied;
	errno_t r = 0;

	debug5("read - io:%p remaining:%d", pio, pio->read_details.remaining);

	/* if read is pending */
	if (pio->read_details.pending) {
		if (w32_io_is_blocking(pio)) {
			debug4("read - io is pending, blocking call made, io:%p", pio);
			while (fileio_is_io_available(pio, TRUE) == FALSE) {
				if (-1 == wait_for_any_event(NULL, 0, INFINITE))
					return -1;
			}
		}
		errno = EAGAIN;
		debug4("read - io is already pending, io:%p", pio);
		return -1;
	}

	if (fileio_is_io_available(pio, TRUE) == FALSE) {
		if (pio->type == NONSOCK_SYNC_FD || FILETYPE(pio) == FILE_TYPE_CHAR) {
			if (-1 == syncio_initiate_read(pio))
				return -1;
		} else {
			if (-1 == fileio_ReadFileEx(pio, (int)max_bytes)) {
				if ((FILETYPE(pio) == FILE_TYPE_PIPE)
					&& (errno == ERROR_BROKEN_PIPE)) {
					/* write end of the pipe closed */
					debug3("read - no more data, io:%p", pio);
					errno = 0;
					return 0;
				}
				/* on W2012, ReadFileEx on file throws a synchronous EOF error*/
				else if ((FILETYPE(pio) == FILE_TYPE_DISK)
					&& (errno == ERROR_HANDLE_EOF)) {
					debug3("read - no more data, io:%p", pio);
					errno = 0;
					return 0;
				}
				return -1;
			}
		}

		/* pick up APC if IO has completed */
		SleepEx(0, TRUE);

		if (w32_io_is_blocking(pio)) {
			while (fileio_is_io_available(pio, TRUE) == FALSE) {
				if (-1 == wait_for_any_event(NULL, 0, INFINITE))
					return -1;
			}
		}
		else if (pio->read_details.pending) {
			errno = EAGAIN;
			debug4("read - IO is pending, io:%p", pio);
			return -1;
		}
	}

	if (pio->read_details.error) {
		errno = errno_from_Win32Error(pio->read_details.error);
		/*write end of the pipe is closed or pipe broken or eof reached*/
		if ((pio->read_details.error == ERROR_BROKEN_PIPE) ||
			(pio->read_details.error == ERROR_HANDLE_EOF)) {
			debug4("read - (2) no more data, io:%p", pio);
			errno = 0;
			pio->read_details.error = 0;
			return 0;
		}
		debug3("read - ERROR from cb :%d, io:%p", errno, pio);
		pio->read_details.error = 0;
		return -1;
	}

	bytes_copied = min((DWORD)max_bytes, pio->read_details.remaining);
	if ((r = memcpy_s(dst, max_bytes, pio->read_details.buf + pio->read_details.completed, bytes_copied)) != 0) {
		debug3("memcpy_s failed with error: %d.", r);
		return -1;
	}
	pio->read_details.remaining -= bytes_copied;
	pio->read_details.completed += bytes_copied;
	debug4("read - io:%p read: %d remaining: %d", pio, bytes_copied,
		pio->read_details.remaining);
	return bytes_copied;
}

VOID CALLBACK 
WriteCompletionRoutine(_In_ DWORD dwErrorCode,
			_In_ DWORD dwNumberOfBytesTransfered,
			_Inout_ LPOVERLAPPED lpOverlapped)
{
	struct w32_io* pio =
		(struct w32_io*)((char*)lpOverlapped - offsetof(struct w32_io, write_overlapped));
	debug4("WriteCB - pio:%p, pending_state:%d, error:%d, transferred:%d of remaining: %d",
		pio, pio->write_details.pending, dwErrorCode, dwNumberOfBytesTransfered,
		pio->write_details.remaining);
	pio->write_details.error = dwErrorCode;
	/* TODO - assert that remaining == dwNumberOfBytesTransfered */
	if ((dwErrorCode == 0) && (pio->write_details.remaining != dwNumberOfBytesTransfered)) {
		error("WriteCB - ERROR: broken assumption, io:%p, wrote:%d, remaining:%d", pio,
			dwNumberOfBytesTransfered, pio->write_details.remaining);
		DebugBreak();
	}
	pio->write_details.remaining -= dwNumberOfBytesTransfered;
	pio->write_details.pending = FALSE;
	*((__int64*)&lpOverlapped->Offset) += dwNumberOfBytesTransfered;
}

/* write() implementation */
int
fileio_write(struct w32_io* pio, const void *buf, size_t max_bytes)
{
	int bytes_copied;
	DWORD pipe_flags = 0, pipe_instances = 0;
	errno_t r = 0;

	debug4("write - io:%p", pio);
	if (pio->write_details.pending) {
		if (w32_io_is_blocking(pio)) {
			debug4("write - io pending, blocking call made, io:%p", pio);
			while (pio->write_details.pending)
				if (wait_for_any_event(NULL, 0, INFINITE) == -1)
					return -1;
		} else {
			errno = EAGAIN;
			debug4("write - IO is already pending, io:%p", pio);
			return -1;
		}
	}

	if (pio->write_details.error) {
		errno = errno_from_Win32Error(pio->write_details.error);
		debug3("write - ERROR:%d on prior unblocking write, io:%p", errno, pio);
		pio->write_details.error = 0;
		if ((FILETYPE(pio) == FILE_TYPE_PIPE) && (errno == ERROR_BROKEN_PIPE)) {
			debug4("write - ERROR:read end of the pipe closed, io:%p", pio);
			errno = EPIPE;
		}
		return -1;
	}

	if (pio->write_details.buf == NULL) {
		pio->write_details.buf = malloc(WRITE_BUFFER_SIZE);
		if (pio->write_details.buf == NULL) {
			errno = ENOMEM;
			debug3("write - ERROR:%d, io:%p", errno, pio);
			return -1;
		}
		pio->write_details.buf_size = WRITE_BUFFER_SIZE;
	}

	bytes_copied = min((int)max_bytes, pio->write_details.buf_size);
	if((r = memcpy_s(pio->write_details.buf, max_bytes, buf, bytes_copied)) != 0) {
		debug3("memcpy_s failed with error: %d.", r);
		return -1;
	}

	if (pio->type == NONSOCK_SYNC_FD || FILETYPE(pio) == FILE_TYPE_CHAR) {
		if (syncio_initiate_write(pio, bytes_copied) == 0) {
			pio->write_details.pending = TRUE;
			pio->write_details.remaining = bytes_copied;
		} else
			return -1;
	} else {
		if (WriteFileEx(WINHANDLE(pio), pio->write_details.buf, bytes_copied,
			&pio->write_overlapped, &WriteCompletionRoutine)) {
			pio->write_details.pending = TRUE;
			pio->write_details.remaining = bytes_copied;
		} else {
			errno = errno_from_Win32LastError();
			/* read end of the pipe closed ?   */
			if ((FILETYPE(pio) == FILE_TYPE_PIPE) && (errno == ERROR_BROKEN_PIPE)) {
				debug3("write - ERROR:read end of the pipe closed, io:%p", pio);
				errno = EPIPE;
			}
			debug3("write ERROR from cb(2):%d, io:%p", errno, pio);
			return -1;
		}
	}

	if (w32_io_is_blocking(pio)) {
		while (pio->write_details.pending) {
			if (wait_for_any_event(NULL, 0, INFINITE) == -1) {
				/* if interrupted but write has completed, we are good*/
				if ((errno != EINTR) || (pio->write_details.pending))
					return -1;
				errno = 0;
			}
		}
	}

	/* execute APC to give a chance for write to complete */
	SleepEx(0, TRUE);

	/* if write has completed, pick up any error reported*/
	if (!pio->write_details.pending && pio->write_details.error) {
		errno = errno_from_Win32Error(pio->write_details.error);
		debug3("write - ERROR from cb:%d, io:%p", pio->write_details.error, pio);
		pio->write_details.error = 0;
		return -1;
	}
	debug4("write - reporting %d bytes written, io:%p", bytes_copied, pio);
	return bytes_copied;
}

/* fstat() implemetation */
int
fileio_fstat(struct w32_io* pio, struct _stat64 *buf)
{
	int fd = _open_osfhandle((intptr_t)pio->handle, 0);
	debug4("fstat - pio:%p", pio);
	if (fd == -1) {
		errno = EOTHER;
		return -1;
	}

	return _fstat64(fd, buf);
}

int
fileio_stat_or_lstat_internal(const char *path, struct _stat64 *buf, int do_lstat)
{
	wchar_t *wpath = NULL;
	char link_test = L'\0';
	HANDLE link_handle = INVALID_HANDLE_VALUE;
	WIN32_FILE_ATTRIBUTE_DATA attributes = { 0 };
	int ret = -1;
	int is_link = 0;

	memset(buf, 0, sizeof(struct _stat64));

	/* Detect root dir */
	if (path && strcmp(path, "/") == 0) {
		buf->st_mode = _S_IFDIR | _S_IREAD | 0xFF;
		buf->st_dev = USHRT_MAX;   // rootdir flag
		return 0;
	}

	if ((wpath = resolved_path_utf16(path)) == NULL)
		return -1;

	/* get the file attributes (or symlink attributes if symlink) */
	if (GetFileAttributesExW(wpath, GetFileExInfoStandard, &attributes) == FALSE) {
		errno = errno_from_Win32LastError();
		goto cleanup;
	}

	/* try to see if it is a symlink */
	is_link = (attributes.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT &&
		fileio_readlink(path, &link_test, 1) == 1);

	/* if doing a stat() on a link, then lookup attributes on the target of the link */
	if (!do_lstat && is_link) {

		/* obtain a file handle to the destination file (not the source link) */
		BY_HANDLE_FILE_INFORMATION link_attributes;
		if ((link_handle = CreateFileW(wpath, 0, 0, NULL, OPEN_EXISTING, 
			FILE_FLAG_BACKUP_SEMANTICS, NULL)) == INVALID_HANDLE_VALUE 
			|| GetFileInformationByHandle(link_handle, &link_attributes) == 0)
		{
			errno = errno_from_Win32LastError();
			goto cleanup;
		}

		/* copy attributes from handle structure to normal structure */
		attributes.ftCreationTime = link_attributes.ftCreationTime;
		attributes.ftLastAccessTime = link_attributes.ftLastAccessTime;
		attributes.ftLastWriteTime = link_attributes.ftLastWriteTime;
		attributes.nFileSizeHigh = link_attributes.nFileSizeHigh;
		attributes.nFileSizeLow = link_attributes.nFileSizeLow;
		attributes.dwFileAttributes = link_attributes.dwFileAttributes;
		is_link = 0;
	}

	buf->st_ino = 0; /* Has no meaning in the FAT, HPFS, or NTFS file systems*/
	buf->st_gid = 0; /* UNIX - specific; has no meaning on windows */
	buf->st_uid = 0; /* UNIX - specific; has no meaning on windows */
	buf->st_nlink = 1; /* number of hard links. Always 1 on non - NTFS file systems.*/
	buf->st_mode |= file_attr_to_st_mode(wpath, attributes.dwFileAttributes);
	buf->st_size = attributes.nFileSizeLow | (((off_t)attributes.nFileSizeHigh) << 32);
	if (wcslen(wpath) > 1 && __ascii_iswalpha(*wpath) && (*(wpath + 1) == ':'))
		buf->st_dev = buf->st_rdev = towupper(*wpath) - L'A'; /* drive num */
	else
		buf->st_dev = buf->st_rdev = _getdrive() - 1;
	file_time_to_unix_time(&(attributes.ftLastAccessTime), &(buf->st_atime));
	file_time_to_unix_time(&(attributes.ftLastWriteTime), &(buf->st_mtime));
	file_time_to_unix_time(&(attributes.ftCreationTime), &(buf->st_ctime));

	/* link type supercedes other file type bits */
	if (is_link) {
		buf->st_mode &= ~S_IFMT;
		buf->st_mode |= S_IFLNK;
	}

	ret = 0;

cleanup:
	if (link_handle != INVALID_HANDLE_VALUE)
		CloseHandle(link_handle);
	if (wpath)
		free(wpath);
	return ret;
}

int
fileio_stat(const char *path, struct _stat64 *buf)
{
	return fileio_stat_or_lstat_internal(path, buf, 0);
}

int
fileio_lstat(const char *path, struct _stat64 *buf)
{
	return fileio_stat_or_lstat_internal(path, buf, 1);
}

long
fileio_lseek(struct w32_io* pio, unsigned __int64 offset, int origin)
{
	debug4("lseek - pio:%p", pio);
	if (origin != SEEK_SET) {
		debug3("lseek - ERROR, origin is not supported %d", origin);
		errno = ENOTSUP;
		return -1;
	}

	pio->write_overlapped.Offset = pio->read_overlapped.Offset = offset & 0xffffffff;
	pio->write_overlapped.OffsetHigh = pio->read_overlapped.OffsetHigh = (offset & 0xffffffff00000000) >> 32;
	 
	return 0;
}

/* fdopen implementation */
FILE*
fileio_fdopen(struct w32_io* pio, const char *mode)
{
	int fd_flags = 0;
	debug4("fdopen - io:%p", pio);

	/* logic below doesn't work with overlapped file HANDLES */
	if (mode[1] == '\0') {
		switch (*mode) {
		case 'r':
			fd_flags = _O_RDONLY;
			break;
		case 'w':
			break;
		case 'a':
			fd_flags = _O_APPEND;
			break;
		default:
			errno = ENOTSUP;
			debug3("fdopen - ERROR unsupported mode %s", mode);
			return NULL;
		}
	} else {
		errno = ENOTSUP;
		debug3("fdopen - ERROR unsupported mode %s", mode);
		return NULL;
	}

	int fd = _open_osfhandle((intptr_t)pio->handle, fd_flags);

	if (fd == -1) {
		errno = EOTHER;
		debug3("fdopen - ERROR:%d _open_osfhandle()", errno);
		return NULL;
	}

	return _fdopen(fd, mode);
}

void
fileio_on_select(struct w32_io* pio, BOOL rd)
{
	if (!rd)
		return;

	if (!pio->read_details.pending && !fileio_is_io_available(pio, rd))
		/* initiate read, record any error so read() will pick up */
		if (pio->type == NONSOCK_SYNC_FD || FILETYPE(pio) == FILE_TYPE_CHAR) {
			if (syncio_initiate_read(pio) != 0) {
				pio->read_details.error = errno;
				errno = 0;
				return;
			}
		} else {
			if (fileio_ReadFileEx(pio, INT_MAX) != 0) {
				pio->read_details.error = errno;
				errno = 0;
				return;
			}
		}
}

int
fileio_close(struct w32_io* pio)
{
	debug4("fileclose - pio:%p", pio);

	if (pio->type == NONSOCK_SYNC_FD || FILETYPE(pio) == FILE_TYPE_CHAR)
		return syncio_close(pio);

	/* handle can be null on AF_UNIX sockets that are not yet connected */
	if (WINHANDLE(pio) == 0 || WINHANDLE(pio) == INVALID_HANDLE_VALUE) {
		free(pio);
		return 0;
	}

	/*
	* we report to POSIX app that an async write has completed as soon its
	* copied to internal buffer. The app may subsequently try to close the
	* fd thinking everything is written. IF the Windows handle is closed
	* now, the pipe/file io write operation may terminate prematurely.
	* To compensate for the discrepency
	* wait here until async write has completed.
	* If you see any process waiting here indefinitely - its because no one
	* is draining from other end of the pipe/file. This is an unfortunate
	* consequence that should otherwise have very little impact on practical
	* scenarios.
	*/
	while (pio->write_details.pending)
		if (0 != wait_for_any_event(NULL, 0, INFINITE))
			return -1;

	CancelIo(WINHANDLE(pio));
	/* let queued APCs (if any) drain */
	SleepEx(0, TRUE);
	CloseHandle(WINHANDLE(pio));
	if (pio->read_details.buf)
		free(pio->read_details.buf);
	if (pio->write_details.buf)
		free(pio->write_details.buf);
	free(pio);

	return 0;
}

BOOL
fileio_is_io_available(struct w32_io* pio, BOOL rd)
{
	if (rd) {
		if (pio->read_details.remaining || pio->read_details.error)
			return TRUE;
		else
			return FALSE;
	} else { /* write */
		return (pio->write_details.pending == FALSE) ? TRUE : FALSE;
	}
}

ssize_t
fileio_readlink(const char *path, char *buf, size_t bufsiz)
{
	/* note: there are two approaches for resolving a symlink in Windows:
	 *
	 * 1) Use CreateFile() to obtain a file handle to the reparse point and
	 *    send using the DeviceIoControl() call to retrieve the link data from the
	 *    reparse point.
	 * 2) Use CreateFile() to obtain a file handle to the target file followed
	 *    by a call to GetFinalPathNameByHandle() to get the real path on the
	 *    file system.
	 *
	 * This approach uses the first method because the second method does not
	 * work on broken link since the target file cannot be opened.  It also
	 * requires additional I/O to read both the symlink and its target.
	 */

	/* abbreviated REPARSE_DATA_BUFFER data structure for decoding symlinks;
	 * the full definition can be found in ntifs.h within the Windows DDK.
	 * we include it here so the DDK does not become prereq to the build.
	 * for more info: https://msdn.microsoft.com/en-us/library/cc232006.aspx
	 */

	typedef struct _REPARSE_DATA_BUFFER_SYMLINK {
		ULONG ReparseTag;
		USHORT ReparseDataLength;
		USHORT Reserved;
		USHORT SubstituteNameOffset;
		USHORT SubstituteNameLength;
		USHORT PrintNameOffset;
		USHORT PrintNameLength;
		ULONG Flags;
		WCHAR PathBuffer[1];
	} REPARSE_DATA_BUFFER_SYMLINK, *PREPARSE_DATA_BUFFER_SYMLINK;

	/* early declarations for cleanup */
	ssize_t ret = -1;
	wchar_t *wpath = NULL;
	wchar_t *linkpath = NULL;
	char *output = NULL;
	HANDLE handle = INVALID_HANDLE_VALUE;
	PREPARSE_DATA_BUFFER_SYMLINK reparse_buffer = NULL;

	/* sanity check */
	if (path == NULL || buf == NULL || bufsiz == 0) {
		errno = EINVAL;
		goto cleanup;
	}

	if ((wpath = resolved_path_utf16(path)) == NULL)
		goto cleanup;

	/* obtain a handle to send to deviceioctl */
	handle = CreateFileW(wpath, 0, 0, NULL, OPEN_EXISTING, 
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, 0);
	if (handle == INVALID_HANDLE_VALUE) {
		errno = errno_from_Win32LastError();
		goto cleanup;
	}

	/* send a request to the file system to get the real path */
	reparse_buffer = (PREPARSE_DATA_BUFFER_SYMLINK) malloc(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
	DWORD dwBytesReturned = 0;
	if (DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, NULL, 0,
		(LPVOID) reparse_buffer, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &dwBytesReturned, 0) == 0) {
		errno = errno_from_Win32LastError();
		goto cleanup;
	}

	/* ensure file is actually symlink */
	if (reparse_buffer->ReparseTag != IO_REPARSE_TAG_SYMLINK) {
		errno = EINVAL;
		goto cleanup;
	}

	/* the symlink structure has a 'Print Name' value that is displayed to the
	 * user which is different from the actual value it uses for redirection
	 * called the 'Substitute Name'; since the Substitute Name has an odd format
	 * that begins with \??\ and it appears that CreateSymbolicLink() always
	 * formats the PrintName value consistently we will just use that
	 */
	int symlink_nonnull_size = reparse_buffer->PrintNameLength;
	wchar_t * symlink_nonnull = &reparse_buffer->PathBuffer[reparse_buffer->PrintNameOffset / sizeof(WCHAR)];

	/* allocate area to hold a null terminated version of the string */
	if ((linkpath = malloc(symlink_nonnull_size + sizeof(wchar_t))) == NULL) {
		goto cleanup;
	}

	/* copy the data out of the reparse buffer and add null terminator */
	memcpy_s(linkpath, symlink_nonnull_size + sizeof(wchar_t), symlink_nonnull, symlink_nonnull_size);
	linkpath[symlink_nonnull_size / sizeof(wchar_t)] = L'\0';

	/* convert link path to utf8 */
	if ((output = utf16_to_utf8(linkpath)) == NULL) {
		errno = ENOMEM;
		goto cleanup;
	}

	/* determine if we need to prepend a forward slash to make this look like
	 * an absolute path C:\Path\Target --> /C:/Path/Target
	 */
	int abs_chars = is_absolute_path(output) ? 1 : 0;
	if (abs_chars)
		buf[0] = '/';

	/* copy link data to output buffer; per specification, truncation is okay */
	convertToForwardslash(output);
	size_t out_size = strlen(output);
	memcpy(buf + abs_chars, output, min(out_size, bufsiz - abs_chars));
	ret = (ssize_t) min(out_size + abs_chars, bufsiz);

cleanup:

	if (linkpath)
		free(linkpath);
	if (reparse_buffer)
		free(reparse_buffer);
	if (handle != INVALID_HANDLE_VALUE)
		CloseHandle(handle);
	if (wpath)
		free(wpath);
	if (output)
		free(output);

	return (ssize_t)ret;
}

int
fileio_symlink(const char *target, const char *linkpath)
{
	DWORD ret = -1;

	if (target == NULL || linkpath == NULL) {
		errno = EFAULT;
		return -1;
	}

	wchar_t *target_utf16 = resolved_path_utf16(target);
	wchar_t *linkpath_utf16 = resolved_path_utf16(linkpath);
	wchar_t *resolved_utf16 = _wcsdup(target_utf16);
	if (target_utf16 == NULL || linkpath_utf16 == NULL)
		goto cleanup;

	if (resolved_utf16 == NULL) {
		errno = ENOMEM;
		goto cleanup;
	}

	/* Relative targets are relative to the link and not our current directory
	 * so attempt to calculate a resolvable path by removing the link file name
	 * leaving only the parent path and then append the relative link:
	 * C:\Path\Link with Link->SubDir\Target to C:\Path\SubDir\Target
	 */
	if (!is_absolute_path(target)) {

		/* allocate area to hold the total possible path */
		free(resolved_utf16);
		size_t resolved_len = (wcslen(target_utf16) + wcslen(linkpath_utf16) + 1);
		resolved_utf16 = malloc(resolved_len * sizeof(wchar_t));
		if (resolved_utf16 == NULL) {
			errno = ENOMEM;
			goto cleanup;
		}

		/* copy the relative target to the end of the link's parent */
		wcscpy_s(resolved_utf16, resolved_len, linkpath_utf16);
		convertToBackslashW(resolved_utf16);
		wchar_t * ptr = wcsrchr(resolved_utf16, L'\\');
		if (ptr == NULL) wcscpy_s(resolved_utf16, resolved_len, target_utf16);
		else wcscpy_s(ptr + 1, resolved_len - (ptr + 1 - resolved_utf16), target_utf16);
	}

	/* unlike other platforms, we need to know whether the symbolic link target is
	 * a file or a directory.  the only way we can confidently do this is to
	 * get the attributes of the target.  therefore, our symlink() has the
	 * limitation of only creating symlink with valid targets
	 */
	WIN32_FILE_ATTRIBUTE_DATA attributes = { 0 };
	if (GetFileAttributesExW(resolved_utf16, GetFileExInfoStandard, &attributes) == FALSE) {
		errno = errno_from_Win32LastError();
		goto cleanup;
	}

	/* use the attribute of the file to determine the proper flag to send */
	DWORD create_flags = (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ?
		SYMBOLIC_LINK_FLAG_DIRECTORY : 0;

	/* symlink creation on earlier versions of windows were a privileged op
 	 * and then an option was added to create symlink using from an unprivileged
 	 * context so we try both operations, attempting privileged version first.
	 * note: 0x2 = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
	 */
	if (CreateSymbolicLinkW(linkpath_utf16, target_utf16, create_flags) == 0) {
		if (CreateSymbolicLinkW(linkpath_utf16, target_utf16, create_flags | 0x2) == 0) {
			errno = errno_from_Win32LastError();
			goto cleanup;
		}
	}
	
	ret = 0;
cleanup:

	if (target_utf16)
		free(target_utf16);
	if (linkpath_utf16)
		free(linkpath_utf16);
	if (resolved_utf16)
		free(resolved_utf16);
	return ret;
}

int 
fileio_link(const char *oldpath, const char *newpath)
{
	DWORD ret = -1;

	if (oldpath == NULL || newpath == NULL) {
		errno = EFAULT;
		return -1;
	}

	wchar_t *oldpath_utf16 = resolved_path_utf16(oldpath);
	wchar_t *newpath_utf16 = resolved_path_utf16(newpath);

	if (oldpath_utf16 == NULL || newpath_utf16 == NULL)
		goto cleanup;

	if (CreateHardLinkW(newpath_utf16, oldpath_utf16, NULL) == 0) {
		errno = errno_from_Win32LastError();
		goto cleanup;
	}

	ret = 0;
cleanup:

	if (oldpath_utf16)
		free(oldpath_utf16);
	if (newpath_utf16)
		free(newpath_utf16);

	return ret;
}