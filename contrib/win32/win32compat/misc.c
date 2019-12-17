/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Author: Bryan Berns <berns@uwalumni.com>
*   Modified group detection use s4u token information 
*
* Copyright(c) 2016 Microsoft Corp.
* All rights reserved
*
* Misc Unix POSIX routine implementations for Windows
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met :
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and / or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define UMDF_USING_NTSTATUS 
#define SECURITY_WIN32
#include <Windows.h>
#include <stdio.h>
#include <time.h>
#include <Shlwapi.h>
#include <conio.h>
#include <LM.h>
#include <Sddl.h>
#include <Aclapi.h>
#include <Ntsecapi.h>
#include <security.h>
#include <ntstatus.h>

#include "inc\unistd.h"
#include "inc\sys\stat.h"
#include "inc\sys\statvfs.h"
#include "inc\sys\time.h"
#include "misc_internal.h"
#include "inc\dlfcn.h"
#include "inc\dirent.h"
#include "inc\sys\types.h"
#include "inc\sys\ioctl.h"
#include "inc\fcntl.h"
#include "inc\utf.h"
#include "signal_internal.h"
#include "misc_internal.h"
#include "debug.h"
#include "w32fd.h"
#include "inc\string.h"
#include "inc\grp.h"
#include "inc\time.h"

#include <wchar.h>

static char* s_programdir = NULL;

/* Maximum reparse buffer info size. The max user defined reparse
 * data is 16KB, plus there's a header. 
 */
#define MAX_REPARSE_SIZE 17000 
#define IO_REPARSE_TAG_SYMBOLIC_LINK IO_REPARSE_TAG_RESERVED_ZERO 
#define IO_REPARSE_TAG_MOUNT_POINT (0xA0000003L) /* winnt ntifs */
#define IO_REPARSE_TAG_HSM (0xC0000004L) /* winnt ntifs */
#define IO_REPARSE_TAG_SIS (0x80000007L) /* winnt ntifs */
#define REPARSE_MOUNTPOINT_HEADER_SIZE 8

 /* Difference in us between UNIX Epoch and Win32 Epoch */
#define EPOCH_DELTA  116444736000000000ULL /* in 100 nsecs intervals */
#define RATE_DIFF 10000000ULL /* 100 nsecs */

#define NSEC_IN_SEC 1000000000ULL // 10**9
#define USEC_IN_SEC 1000000ULL // 10**6

/* Windows CRT defines error string messages only till 43 in errno.h
 * This is an extended list that defines messages for EADDRINUSE through EWOULDBLOCK
 */
char* _sys_errlist_ext[] = {
	"Address already in use",				/* EADDRINUSE      100 */
	"Address not available",				/* EADDRNOTAVAIL   101 */
	"Address family not supported",				/* EAFNOSUPPORT    102 */
	"Connection already in progress",			/* EALREADY        103 */
	"Bad message",						/* EBADMSG         104 */
	"Operation canceled",					/* ECANCELED       105 */
	"Connection aborted",					/* ECONNABORTED    106 */
	"Connection refused",					/* ECONNREFUSED    107 */
	"Connection reset",					/* ECONNRESET      108 */
	"Destination address required",				/* EDESTADDRREQ    109 */
	"Host is unreachable",					/* EHOSTUNREACH    110 */
	"Identifier removed",					/* EIDRM           111 */
	"Operation in progress",				/* EINPROGRESS     112 */
	"Socket is connected",					/* EISCONN         113 */
	"Too many levels of symbolic links",			/* ELOOP           114 */
	"Message too long",					/* EMSGSIZE        115 */
	"Network is down",					/* ENETDOWN        116 */
	"Connection aborted by network",			/* ENETRESET       117 */
	"Network unreachable",					/* ENETUNREACH     118 */
	"No buffer space available",				/* ENOBUFS         119 */
	"No message is available on the STREAM head read queue",/* ENODATA         120 */
	"Link has been severed",				/* ENOLINK         121 */
	"No message of the desired type",			/* ENOMSG          122 */
	"Protocol not available",				/* ENOPROTOOPT     123 */
	"No STREAM resources",					/* ENOSR           124 */
	"Not a STREAM",						/* ENOSTR          125 */
	"The socket is not connected",				/* ENOTCONN        126 */
	"enotrecoverable",					/* ENOTRECOVERABLE 127 */
	"Not a socket",						/* ENOTSOCK        128 */
	"Operation not supported",				/* ENOTSUP         129 */
	"Operation not supported on socket",			/* EOPNOTSUPP      130 */
	"eother",						/* EOTHER          131 */
	"Value too large to be stored in data type",		/* EOVERFLOW       132 */
	"eownerdead",						/* EOWNERDEAD      133 */
	"Protocol error",					/* EPROTO          134 */
	"Protocol not supported",				/* EPROTONOSUPPORT 135 */
	"Protocol wrong type for socket",			/* EPROTOTYPE      136 */
	"Timer expired",					/* ETIME           137 */
	"Connection timed out",					/* ETIMEDOUT       138 */
	"Text file busy",					/* ETXTBSY         139 */
	"Operation would block"					/* EWOULDBLOCK     140 */
};

/* chroot state */
char* chroot_path = NULL;
int chroot_path_len = 0;
/* UTF-16 version of the above */
wchar_t* chroot_pathw = NULL;

int
usleep(unsigned int useconds)
{
	Sleep(useconds / 1000);
	return 1;
}

static LONGLONG
timespec_to_nsec(const struct timespec *req)
{
	LONGLONG sec = req->tv_sec;
	return sec * NSEC_IN_SEC + req->tv_nsec;
}


int
nanosleep(const struct timespec *req, struct timespec *rem)
{
	HANDLE timer;
	LARGE_INTEGER li;

	if (req->tv_sec < 0 || req->tv_nsec < 0 || req->tv_nsec > 999999999) {
		errno = EINVAL;
		return -1;
	}

	if ((timer = CreateWaitableTimerW(NULL, TRUE, NULL)) == NULL) {
		errno = EFAULT;
		return -1;
	}

	/* convert timespec to 100ns intervals */
	li.QuadPart = -(timespec_to_nsec(req) / 100);
	if (!SetWaitableTimer(timer, &li, 0, NULL, NULL, FALSE)) {
		CloseHandle(timer);
		errno = EFAULT;
		return -1;
	}

	/* TODO - use wait_for_any_event, since we want to wake up on interrupts*/
	switch (WaitForSingleObject(timer, INFINITE)) {
	case WAIT_OBJECT_0:
		CloseHandle(timer);
		return 0;
	default:
		CloseHandle(timer);
		errno = EFAULT;
		return -1;
	}
}

/* This routine is contributed by  * Author: NoMachine <developers@nomachine.com>
 * Copyright (c) 2009, 2010 NoMachine
 * All rights reserved
 */
int
gettimeofday(struct timeval *tv, void *tz)
{
	union {
		FILETIME ft;
		unsigned long long ns;
	} timehelper;
	unsigned long long us;

	/* Fetch time since Jan 1, 1601 in 100ns increments */
	GetSystemTimeAsFileTime(&timehelper.ft);	

	/* Remove the epoch difference & convert 100ns to us */
	us = (timehelper.ns - EPOCH_DELTA) / 10;

	/* Stuff result into the timeval */
	tv->tv_sec = (long)(us / USEC_IN_SEC);
	tv->tv_usec = (long)(us % USEC_IN_SEC);

	return 0;
}

void
explicit_bzero(void *b, size_t len)
{
	SecureZeroMemory(b, len);
}

static DWORD last_dlerror = ERROR_SUCCESS;

HMODULE
dlopen(const char *filename, int flags)
{
	wchar_t *wfilename = utf8_to_utf16(filename);
	if (wfilename == NULL) {
		last_dlerror = ERROR_INVALID_PARAMETER;
		return NULL;
	}

	HMODULE module = LoadLibraryW(wfilename);
	if (module == NULL)
		last_dlerror = GetLastError();

	free(wfilename);
	return module;
}

int
dlclose(HMODULE handle)
{
	FreeLibrary(handle);
	return 0;
}

void *
dlsym(HMODULE handle, const char *symbol)
{
	void *ptr = GetProcAddress(handle, symbol);
	if (ptr == NULL)
		last_dlerror = GetLastError();
	return ptr;
}

char *
dlerror()
{
	static char *message = NULL;
	if (message != NULL) {
		free(message);
		message = NULL;
	}
	if (last_dlerror == ERROR_SUCCESS)
		return NULL;

	wchar_t *wmessage = NULL;
	DWORD length = FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, last_dlerror, 0, (wchar_t *) &wmessage, 0, NULL);
	last_dlerror = ERROR_SUCCESS;

	if (length == 0)
		goto error;

	if (wmessage[length - 1] == L'\n')
		wmessage[length - 1] = L'\0';
	if (length > 1 && wmessage[length - 2] == L'\r')
		wmessage[length - 2] = L'\0';

	message = utf16_to_utf8(wmessage);
	LocalFree(wmessage);

	if (message == NULL)
		goto error;

	return message;

error:
	return "Failed to format error message";
}

/*fopen on Windows to mimic https://linux.die.net/man/3/fopen
* only r, w, a are supported for now
*/
FILE *
w32_fopen_utf8(const char *input_path, const char *mode)
{
	wchar_t *wmode = NULL, *wpath = NULL;
	FILE* f = NULL;
	char utf8_bom[] = { 0xEF,0xBB,0xBF };
	char first3_bytes[3];
	int status = 1;
	errno_t r = 0;
	int nonfs_dev = 0; /* opening a non file system device */

	if (mode == NULL || mode[1] != '\0') {
		errno = ENOTSUP;
		return NULL;
	}

	if(NULL == input_path) { 
		errno = EINVAL;
		debug3("fopen - ERROR:%d", errno);
		return NULL; 
	}

	/* if opening null device, point to Windows equivalent */
	if (strncmp(input_path, NULL_DEVICE, sizeof(NULL_DEVICE)) == 0
		|| strncmp(input_path, NULL_DEVICE_WIN, sizeof(NULL_DEVICE_WIN)) == 0) {
		nonfs_dev = 1;
		wpath = utf8_to_utf16(NULL_DEVICE_WIN);
	}
	else
		wpath = resolved_path_utf16(input_path);
	
	wmode = utf8_to_utf16(mode);
	if (wpath == NULL || wmode == NULL)
		goto cleanup;

	if ((_wfopen_s(&f, wpath, wmode) != 0) || (f == NULL)) {
		debug3("Failed to open file:%S error:%d", wpath, errno);
		goto cleanup;
	}	

	if (chroot_pathw && !nonfs_dev) {
		/* ensure final path is within chroot */
		HANDLE h = (HANDLE)_get_osfhandle(_fileno(f));
		if (!file_in_chroot_jail(h)) {
			debug3("%s is not in chroot jail", input_path);
			fclose(f);
			f = NULL;
			errno = EACCES;
			goto cleanup;
		}
	}

	/* BOM adjustments for file streams*/
	if (mode[0] == 'w' && fseek(f, 0, SEEK_SET) != EBADF) {
		/* write UTF-8 BOM - should we ?*/
		/*if (fwrite(utf8_bom, sizeof(utf8_bom), 1, f) != 1) {
			fclose(f);
			goto cleanup;
		}*/

	} else if (mode[0] == 'r' && fseek(f, 0, SEEK_SET) != EBADF) {
		/* read out UTF-8 BOM if present*/
		if (fread(first3_bytes, 3, 1, f) != 1 ||
			memcmp(first3_bytes, utf8_bom, 3) != 0) {
			fseek(f, 0, SEEK_SET);
		}
	}

cleanup:

	if (wpath) 
		free(wpath);
	if (wmode)
		free(wmode);

	return f;
}

/*
* fgets to support Unicode input 
* each UTF-16 char may bloat up to 4 utf-8 chars. We cannot determine if the length of 
* input unicode string until it is readed and converted to utf8 string.
* There is a risk to miss on unicode char when last unicode char read from console
* does not fit the remain space in str. use cautiously. 
*/
char*
 w32_fgets(char *str, int n, FILE *stream) {
	if (!str || !n || !stream) return NULL;

	HANDLE h = (HANDLE)_get_osfhandle(_fileno(stream));
	wchar_t* str_w = NULL;
	char *ret = NULL, *str_tmp = NULL, *cp = NULL;
	int actual_read = 0;
	errno_t r = 0;

	if (h != NULL && h != INVALID_HANDLE_VALUE
	    && GetFileType(h) == FILE_TYPE_CHAR) {

		/* Allocate memory for one UTF-16 char (up to 4 bytes) and a terminate char (\0) */
		if ((str_w = malloc(3 * sizeof(wchar_t))) == NULL) {
			errno = ENOMEM;
			goto cleanup;
		}
		/* prepare for Unicode input */
		_setmode(_fileno(stream), O_U16TEXT);
		cp = str;
		/*
		* each UTF-16 char may bloat up to 4 utf-8 chars
		* read one wide chars at time from console and convert it to utf8
		* stop reading until reach '\n' or the converted utf8 string length is n-1
		*/
		do {
			if (str_tmp)
				free(str_tmp);			
			if (fgetws(str_w, 2, stream) == NULL)
				goto cleanup;
			if ((str_tmp = utf16_to_utf8(str_w)) == NULL) {
				debug3("utf16_to_utf8 failed!");
				errno = ENOMEM;
				goto cleanup;
			}
			
			if((actual_read + (int)strlen(str_tmp)) >= n)
				break;
			if ((r = memcpy_s(cp, n - actual_read, str_tmp, strlen(str_tmp))) != 0) {
				debug3("memcpy_s failed with error: %d.", r);
				goto cleanup;
			}
			actual_read += (int)strlen(str_tmp);
			cp += strlen(str_tmp);
			
		} while ((actual_read < n - 1) && *str_tmp != '\n');
		*cp = '\0';

		if (actual_read > n - 1) {
			/* shouldn't happen. but handling in case */
			debug3("actual_read %d exceeds the limit:%d", actual_read, n-1);
			errno = EINVAL;
			goto cleanup;
		}		
		ret = str;
	}
	else
		ret = fgets(str, n, stream);
cleanup:
	if (str_w)
		free(str_w);
	if (str_tmp)
		free(str_tmp);
	return ret;
}

/* Account for differences between Unix's and Windows versions of setvbuf */
int 
w32_setvbuf(FILE *stream, char *buffer, int mode, size_t size) {
	
	/* BUG: setvbuf on console stream interferes with Unicode I/O	*/
	HANDLE h = (HANDLE)_get_osfhandle(_fileno(stream));
	
	if (h != NULL && h != INVALID_HANDLE_VALUE
	    && GetFileType(h) == FILE_TYPE_CHAR)
		return 0;

	/* BUG: setvbuf on file stream is interfering with w32_fopen */
	/* short circuit for now*/
	return 0;

	/*
	 * if size is 0, set no buffering. 
	 * Windows does not differentiate __IOLBF and _IOFBF
	 */
	if (size == 0)
		return setvbuf(stream, NULL, _IONBF, 0);
	else
		return setvbuf(stream, buffer, mode, size);
}

int
daemon(int nochdir, int noclose)
{
	FreeConsole();
	return 0;
}

int
w32_ioctl(int d, int request, ...)
{
	va_list valist;
	va_start(valist, request);

	switch (request) {
	case TIOCGWINSZ: {
		struct winsize* wsize = va_arg(valist, struct winsize*);
		CONSOLE_SCREEN_BUFFER_INFO c_info;
		if (wsize == NULL || !GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &c_info)) {
			errno = EINVAL;
			return -1;
		}

		wsize->ws_col = c_info.dwSize.X;
		wsize->ws_row = c_info.srWindow.Bottom - c_info.srWindow.Top + 1;
		wsize->ws_xpixel = 640;
		wsize->ws_ypixel = 480;

		return 0;
	}
	default:
		errno = ENOTSUP;
		return -1;
	}
}

/* p should be at least 12 bytes long*/
void
strmode(mode_t mode, char *p)
{
	/* print type */
	switch (mode & S_IFMT) {
	case S_IFDIR:			/* directory */
		*p++ = 'd';
		break;
	case S_IFCHR:			/* character special */
		*p++ = 'c';
		break;
	case S_IFREG:			/* regular */
		*p++ = '-';
		break;
	case S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		break;			
#ifdef S_IFSOCK
	case S_IFSOCK:			/* socket */
		*p++ = 's';
		break;
#endif
	case _S_IFIFO:			/* fifo */
		*p++ = 'p';
		break;
	default:			/* unknown */
		*p++ = '?';
		break;
	}

	/* group, other are not applicable on the windows */

	/* usr */
	if (mode & S_IREAD)
		*p++ = 'r';
	else
		*p++ = '-';
	if (mode & S_IWRITE)
		*p++ = 'w';
	else
		*p++ = '-';
	if (mode & S_IEXEC)
		*p++ = 'x';
	else
		*p++ = '-';

	const char *permissions = "****** ";	
	for(int i = 0; i < (int)strlen(permissions); i++)
		*p++ = permissions[i];
	
	*p = '\0';
}

int
w32_chmod(const char *pathname, mode_t mode)
{
	/* TODO - 
	 * _wchmod() doesn't behave like unix "chmod" command.
	 * _wchmod() only toggles the read-only bit and it doesn't touch ACL.
	 */	
	int ret;
	wchar_t *resolvedPathName_utf16 = resolved_path_utf16(pathname);
	if (resolvedPathName_utf16 == NULL) 
		return -1;

	ret = _wchmod(resolvedPathName_utf16, mode);
	free(resolvedPathName_utf16);
	return ret;
}

int
w32_chown(const char *pathname, unsigned int owner, unsigned int group)
{
	/* TODO - implement this */
	errno = EOPNOTSUPP;
	return -1;
}

int 
w32_fchown( int fd, unsigned int owner, unsigned int group)
{
	/* TODO - implement this */
	errno = EOPNOTSUPP;
	return -1;
}

/* Convert a UNIX time into a Windows file time */
void
unix_time_to_file_time(ULONG t, LPFILETIME pft)
{
	ULONGLONG ull;
	ull = UInt32x32To64(t, RATE_DIFF) + EPOCH_DELTA;

	pft->dwLowDateTime = (DWORD)ull;
	pft->dwHighDateTime = (DWORD)(ull >> 32);
}

/* Convert a Windows file time into a UNIX time_t */
void
file_time_to_unix_time(const LPFILETIME pft, time_t * winTime)
{
	*winTime = ((long long)pft->dwHighDateTime << 32) + pft->dwLowDateTime;
	*winTime -= EPOCH_DELTA;
	*winTime /= RATE_DIFF;		 /* Nano to seconds resolution */
}

static BOOL
is_root_or_empty(wchar_t * path)
{
	wchar_t * path_start;
	int len;
	if (!path) 
		return FALSE;
	len = (int)wcslen(path);
	if((len > 1) && __ascii_iswalpha(path[0]) && path[1] == L':')
		path_start = path + 2;
	else
		path_start = path;
	/*path like  c:\, /, \ are root directory*/
	if ((*path_start == L'\0') || ((*path_start == L'\\' || *path_start == L'/' ) && path_start[1] == L'\0'))
		return TRUE;
	return FALSE;
}

static BOOL
has_executable_extension(wchar_t * path)
{
	wchar_t * last_dot;
	if (!path)
		return FALSE;

	last_dot = wcsrchr(path, L'.');
	if (!last_dot)
		return FALSE;
	if (_wcsnicmp(last_dot, L".exe", 4) != 0 && _wcsnicmp(last_dot, L".cmd", 4) != 0 &&
	_wcsnicmp(last_dot, L".bat", 4) != 0 && _wcsnicmp(last_dot, L".com", 4) != 0)
		return FALSE; 
	return TRUE;
}

int
file_attr_to_st_mode(wchar_t * path, DWORD attributes)
{
	int mode = S_IREAD;
	BOOL isReadOnlyFile = FALSE;
	if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 || is_root_or_empty(path))
		mode |= S_IFDIR | _S_IEXEC;
	else {
		mode |= S_IFREG;
		/* See if file appears to be an executable by checking its extension */
		if (has_executable_extension(path))
			mode |= _S_IEXEC;

	}
	if (!(attributes & FILE_ATTRIBUTE_READONLY))
		mode |= S_IWRITE;
	else
		isReadOnlyFile = TRUE;

	// We don't populate the group permissions as its not applicable to windows OS.
	// propagate owner read/write/execute bits to other fields.	
	mode |= get_others_file_permissions(path, isReadOnlyFile);

	return mode;
}

static int
settimes(wchar_t * path, FILETIME *cretime, FILETIME *acttime, FILETIME *modtime)
{
	HANDLE handle;
	handle = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (handle == INVALID_HANDLE_VALUE) {
		/* TODO - convert Win32 error to errno */
		errno = GetLastError();
		debug3("w32_settimes - CreateFileW ERROR:%d", errno);
		return -1;
	}

	if (SetFileTime(handle, cretime, acttime, modtime) == 0) {
		errno = GetLastError();
		debug3("w32_settimes - SetFileTime ERROR:%d", errno);
		CloseHandle(handle);
		return -1;
	}

	CloseHandle(handle);
	return 0;
}

int
w32_utimes(const char *filename, struct timeval *tvp)
{
	int ret;
	FILETIME acttime, modtime;
	wchar_t *resolvedPathName_utf16 = resolved_path_utf16(filename);
	if (resolvedPathName_utf16 == NULL) 
		return -1;

	memset(&acttime, 0, sizeof(FILETIME));
	memset(&modtime, 0, sizeof(FILETIME));

	unix_time_to_file_time((ULONG)tvp[0].tv_sec, &acttime);
	unix_time_to_file_time((ULONG)tvp[1].tv_sec, &modtime);
	ret = settimes(resolvedPathName_utf16, NULL, &acttime, &modtime);
	free(resolvedPathName_utf16);
	return ret;
}

int
w32_symlink(const char *target, const char *linkpath)
{
	return fileio_symlink(target, linkpath);
}

int
w32_link(const char *oldpath, const char *newpath)
{
	return fileio_link(oldpath, newpath);
}

int
w32_rename(const char *old_name, const char *new_name)
{
	if (old_name == NULL || new_name == NULL) {
		errno = EFAULT;
		return -1;
	}

	wchar_t *resolvedOldPathName_utf16 = resolved_path_utf16(old_name);
	wchar_t *resolvedNewPathName_utf16 = resolved_path_utf16(new_name);

	if (NULL == resolvedOldPathName_utf16 || NULL == resolvedNewPathName_utf16) 
		return -1;
	
	/*
	 * To be consistent with POSIX rename(),
	 * 1) if the new_name is file, then delete it so that _wrename will succeed.
	 * 2) if the new_name is directory and it is empty then delete it so that _wrename will succeed.
	 */
	struct _stat64 st_new;
	struct _stat64 st_old;
	if ((fileio_stat(new_name, &st_new) != -1) &&
	    (fileio_stat(old_name, &st_old) != -1)) {
		if (((st_old.st_mode & _S_IFMT) == _S_IFREG) &&
		    ((st_new.st_mode & _S_IFMT) == _S_IFREG))
			w32_unlink(new_name);

		if (((st_old.st_mode & _S_IFMT) == _S_IFDIR) &&
		    ((st_new.st_mode & _S_IFMT) == _S_IFDIR)) {
			DIR *dirp = opendir(new_name);
			if (NULL != dirp) {
				struct dirent *dp = readdir(dirp);
				closedir(dirp);

				if (dp == NULL)
					w32_rmdir(new_name);
			}
		}
	}

	int returnStatus = _wrename(resolvedOldPathName_utf16, resolvedNewPathName_utf16);
	free(resolvedOldPathName_utf16);
	free(resolvedNewPathName_utf16);

	return returnStatus;
}

int
w32_unlink(const char *path)
{
	wchar_t *resolvedPathName_utf16 = resolved_path_utf16(path);
	if (NULL == resolvedPathName_utf16) 
		return -1;

	int returnStatus = _wunlink(resolvedPathName_utf16);
	free(resolvedPathName_utf16);

	return returnStatus;
}

int
w32_rmdir(const char *path)
{
	wchar_t *resolvedPathName_utf16 = resolved_path_utf16(path);
	if (NULL == resolvedPathName_utf16) 
		return -1;

	int returnStatus = _wrmdir(resolvedPathName_utf16);
	free(resolvedPathName_utf16);

	return returnStatus;
}

int
w32_chdir(const char *dirname_utf8)
{
	wchar_t *dirname_utf16 = resolved_path_utf16(dirname_utf8);
	if (dirname_utf16 == NULL) 
		return -1;

	int returnStatus = _wchdir(dirname_utf16);
	free(dirname_utf16);

	return returnStatus;
}

char *
w32_getcwd(char *buffer, int maxlen)
{
	if(!buffer) return NULL;

	wchar_t wdirname[PATH_MAX];
	char* putf8 = NULL;

	if (_wgetcwd(wdirname, PATH_MAX) == NULL)
		return NULL;

	if ((putf8 = utf16_to_utf8(wdirname)) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	if ((int)strlen(putf8) >= maxlen) {
		errno = ERANGE;
		free(putf8);
		return NULL;
	}

	if (strcpy_s(buffer, maxlen, putf8))
		return NULL;
	free(putf8);

	to_lower_case(buffer);

	if (chroot_path) {
		/* ensure we are within chroot jail */
		char c = buffer[chroot_path_len];
		if ((int)strlen(buffer) < chroot_path_len ||
		    memcmp(chroot_path, buffer, chroot_path_len) != 0 ||
		    (c != '\0' && c!= '\\') ) {
			errno = EOTHER;
			error("cwd is not currently within chroot");
			return NULL;
		}

		/* is cwd chroot ?*/
		if (c == '\0') {
			buffer[0] = '\\';
			buffer[1] = '\0';
		}
		else {
			char *tail = buffer + chroot_path_len;
			memmove_s(buffer, maxlen, tail, strlen(tail) + 1);
		}
	} 

	return buffer;
}

int
w32_mkdir(const char *path_utf8, unsigned short mode)
{
	int curmask;
	wchar_t *path_utf16 = resolved_path_utf16(path_utf8);
	if (path_utf16 == NULL) 
		return -1;

	int returnStatus = _wmkdir(path_utf16);
	if (returnStatus < 0) {
		free(path_utf16);
		return -1;
	}

	errno_t error = _umask_s(0, &curmask);
	if(!error)
		_umask_s(curmask, &curmask);

	returnStatus = _wchmod(path_utf16, mode & ~curmask & (_S_IREAD | _S_IWRITE));
	free(path_utf16);

	return returnStatus;
}

int
w32_stat(const char *input_path, struct w32_stat *buf)
{
	return fileio_stat(input_path, (struct _stat64*)buf);
}

int
w32_lstat(const char *input_path, struct w32_stat *buf)
{
	return fileio_lstat(input_path, (struct _stat64*)buf);
}

/* if file is symbolic link, copy its link into "link" */
int
w32_readlink(const char *path, char *link, int linklen)
{
	return fileio_readlink(path, link, linklen);
}

/* convert forward slash to back slash */
void
convertToBackslash(char *str)
{
	while (*str) {
		if (*str == '/')
			*str = '\\';
		str++;
	}
}

void
convertToBackslashW(wchar_t *str)
{
	while (*str) {
		if (*str == L'/')
			*str = L'\\';
		str++;
	}
}

/* convert back slash to forward slash */
void
convertToForwardslash(char *str)
{
	while (*str) {
		if (*str == '\\')
			*str = '/';
		str++;
	}
}

/*
 * This method will resolves references to /./, /../ and extra '/' characters in the null-terminated string named by
 *  path to produce a canonicalized absolute pathname.
 */
char *
realpath(const char *inputpath, char * resolved)
{
	wchar_t* temppath_utf16 = NULL;
	wchar_t* resolved_utf16 = NULL;
	char path[PATH_MAX] = { 0, }, tempPath[PATH_MAX] = { 0, }, *ret = NULL;
	int is_win_path = 1;

	if (!inputpath || !resolved)
		return NULL;
	
	size_t path_len = strlen(inputpath);
	resolved[0] = '\0';

	if (path_len > PATH_MAX) {
		errno = EINVAL;
		return NULL;
	}

	if (is_bash_test_env() && bash_to_win_path(inputpath, path, _countof(path)))
		is_win_path = 0;

	if (is_win_path) {
		if (_strnicmp(inputpath, PROGRAM_DATA, strlen(PROGRAM_DATA)) == 0) {
			strcpy_s(path, PATH_MAX, __progdata);
			strcat_s(path, PATH_MAX, &inputpath[strlen(PROGRAM_DATA)]);
		} else {
			memcpy_s(path, PATH_MAX, inputpath, strlen(inputpath));
		}
	}

	path_len = strlen(path);
	if (path_len > PATH_MAX) {
		errno = EINVAL;
		return NULL;
	}

	/* resolve root directory to the same */
	if (path_len == 1 && (path[0] == '/' || path[0] == '\\')) {
		resolved[0] = '/';
		resolved[1] = '\0';
		ret = resolved;
		goto done;
	}

	/* resolve this common case scenario to root */
	/* "cd .." from within a drive root */
	if (path_len == 6 && !chroot_path) {
		char *tmplate = "/x:/..";
		strcat_s(resolved, PATH_MAX, path);
		resolved[1] = 'x';
		if (strcmp(tmplate, resolved) == 0) {
			resolved[0] = '/';
			resolved[1] = '\0';
			ret = resolved;
			goto done;
		}
	}

	if (chroot_path) {
		resolved[0] = '\0';
		strcat_s(resolved, PATH_MAX, chroot_path);
		/* if path is relative, add cwd within chroot */
		if (path[0] != '/' && path[0] != '\\') {
			w32_getcwd(resolved + chroot_path_len, PATH_MAX - chroot_path_len);
			strcat_s(resolved, PATH_MAX, "/");
		}
		/* TODO - This logic will fail if the chroot_path is more than PATH_MAX/2.
		 * resolved variable is of PATH_MAX.
		 * We first copy chroot_path to resolved variable then incoming path (which can be again chroot_path).
		 * In this case strcat_s will thrown a run time insufficient buffer exception.
		 */
		strcat_s(resolved, PATH_MAX, path);
	}
	else if ((path_len >= 2) && (path[0] == '/') && path[1] && (path[2] == ':')) {
		if((errno = strncpy_s(resolved, PATH_MAX, path + 1, path_len)) != 0 ) /* skip the first '/' */ {
			debug3("memcpy_s failed with error: %d.", errno);
			goto done;
		}
	}
	else if(( errno = strncpy_s(resolved, PATH_MAX, path, path_len + 1)) != 0) {
		debug3("memcpy_s failed with error: %d.", errno);
		goto done;
	}

	if ((resolved[0]) && (resolved[1] == ':') && (resolved[2] == '\0')) { /* make "x:" as "x:\\" */
		resolved[2] = '\\';
		resolved[3] = '\0';
	}

	/* note: _wfullpath() is required to resolve paths containing unicode characters */
	if ((resolved_utf16 = utf8_to_utf16(resolved)) == NULL ||
		(temppath_utf16 = _wfullpath(NULL, resolved_utf16, 0)) == NULL ||
		WideCharToMultiByte(CP_UTF8, 0, temppath_utf16, -1, tempPath, sizeof(tempPath), NULL, NULL) == 0) {
		errno = EINVAL;
		goto done;
	}

	if (chroot_path) {
		if (strlen(tempPath) < strlen(chroot_path)) {
			errno = EACCES;
			goto done;
		}
		if (memcmp(chroot_path, tempPath, strlen(chroot_path)) != 0) {
			errno = EACCES;
			goto done;
		}

		resolved[0] = '\0';
		
		if (strlen(tempPath) == strlen(chroot_path))
			/* realpath is the same as chroot_path */
			strcat_s(resolved, PATH_MAX, "\\");
		else
			strcat_s(resolved, PATH_MAX, tempPath + strlen(chroot_path));

		if (resolved[0] != '\\') {
			errno = EACCES;
			goto done;
		}

		convertToForwardslash(resolved);
		ret = resolved;
		goto done;
	}
	else {
		convertToForwardslash(tempPath);
		resolved[0] = '/'; /* will be our first slash in /x:/users/test1 format */
		if ((errno = strncpy_s(resolved + 1, PATH_MAX - 1, tempPath, sizeof(tempPath) - 1)) != 0) {
			debug3("memcpy_s failed with error: %d.", errno);
			goto done;
		}
		ret = resolved;
		goto done;
	}

done:
	if (resolved_utf16 != NULL)
		free(resolved_utf16);
	if (temppath_utf16 != NULL)
		free(temppath_utf16);
	return ret;
}

/* on error returns NULL and sets errno */
char* 
resolved_path_utf8(const char *input_path)
{
	wchar_t *resolved_path_w = resolved_path_utf16(input_path);
	char *resolved_path = NULL;

	if (resolved_path_w) {
		resolved_path = utf16_to_utf8(resolved_path_w);
		free(resolved_path_w);
	}

	return resolved_path;
}

/* on error returns NULL and sets errno */
wchar_t*
resolved_path_utf16(const char *input_path)
{
	wchar_t *resolved_path = NULL;
	char real_path[PATH_MAX];

	if (!input_path) {
		errno = EINVAL;
		return NULL;
	}

	if (realpath(input_path, real_path) == NULL)
		return NULL;

	if (chroot_path) {
		char actual_path[PATH_MAX] = { 0 };
		strcat_s(actual_path, _countof(actual_path), chroot_path);
		strcat_s(actual_path, _countof(actual_path), real_path);
		resolved_path = utf8_to_utf16(actual_path);
	} else {
		if ((strlen(real_path) == 1) && (real_path[0] == '/'))
			resolved_path = utf8_to_utf16(real_path);
		else
			resolved_path = utf8_to_utf16(real_path + 1); /* account for preceding / in real_path */
	}

	return resolved_path;
}

int
statvfs(const char *path, struct statvfs *buf)
{
	DWORD sectorsPerCluster;
	DWORD bytesPerSector;
	DWORD freeClusters;
	DWORD totalClusters;

	wchar_t* path_utf16 = resolved_path_utf16(path);
	if (path_utf16 == NULL)
		return -1;

	if (GetDiskFreeSpaceW(path_utf16, &sectorsPerCluster, &bytesPerSector,
	    &freeClusters, &totalClusters)) {
		debug5("path              : [%s]", path);
		debug5("sectorsPerCluster : [%lu]", sectorsPerCluster);
		debug5("bytesPerSector    : [%lu]", bytesPerSector);
		debug5("bytesPerCluster   : [%lu]", sectorsPerCluster * bytesPerSector);
		debug5("freeClusters      : [%lu]", freeClusters);
		debug5("totalClusters     : [%lu]", totalClusters);

		buf->f_bsize = sectorsPerCluster * bytesPerSector;
		buf->f_frsize = sectorsPerCluster * bytesPerSector;
		buf->f_blocks = totalClusters;
		buf->f_bfree = freeClusters;
		buf->f_bavail = freeClusters;
		buf->f_files = -1;
		buf->f_ffree = -1;
		buf->f_favail = -1;
		buf->f_fsid = 0;
		buf->f_flag = 0;
		buf->f_namemax = PATH_MAX - 1;

		free(path_utf16);
		return 0;
	} else {
		debug5("ERROR: Cannot get free space for [%s]. Error code is : %d.", path, GetLastError());
		errno = errno_from_Win32LastError();
		free(path_utf16);
		return -1;
	}
}

int
fstatvfs(int fd, struct statvfs *buf)
{
	errno = ENOTSUP;
	return -1;
}

char *
w32_strerror(int errnum)
{
	if (errnum >= EADDRINUSE  && errnum <= EWOULDBLOCK)
		return _sys_errlist_ext[errnum - EADDRINUSE];
	
	strerror_s(errorBuf, ERROR_MSG_MAXLEN, errnum);
	return errorBuf;
}

char *
readpassphrase(const char *prompt, char *outBuf, size_t outBufLen, int flags)
{
	int current_index = 0;
	int utf8_read = 0;
	char utf8_char[4];
	wchar_t ch;
	wchar_t* wtmp = NULL;

	if (outBufLen == 0) {
		errno = EINVAL;
		return NULL;
	}

	while (_kbhit()) _getwch();

	wtmp = utf8_to_utf16(prompt);
	if (wtmp == NULL)
		fatal("unable to alloc memory");

	_cputws(wtmp);
	free(wtmp);

	while (current_index < (int)outBufLen - 1) {
		ch = _getwch();
		
		if (ch == L'\r') {
			if (_kbhit()) _getwch(); /* read linefeed if its there */
			break;
		} else if (ch == L'\n') {
			break;
		} else if (ch == L'\b') { /* backspace */
			if (current_index > 0) {
				if (flags & RPP_ECHO_ON)
					wprintf_s(L"%c \b", ch);

				/* overwrite last character - remove any utf8 extended chars */
				while (current_index > 0 && (outBuf[current_index - 1] & 0xC0) == 0x80)
					current_index--;

				/* overwrite last character - remove first utf8 byte */
				if (current_index > 0)
					current_index--;
			}
		} else if (ch == L'\003') { /* exit on Ctrl+C */
			fatal("");
		} else {
			if (flags & RPP_SEVENBIT)
				ch &= 0x7f;

			if (iswalpha(ch)) {
				if(flags & RPP_FORCELOWER)
					ch = towlower(ch);
				if(flags & RPP_FORCEUPPER)
					ch = towupper(ch);
			}

			/* convert unicode to utf8 characters */
			int utf8_char_size = sizeof(utf8_char);
			if ((utf8_read = WideCharToMultiByte(CP_UTF8, 0, &ch, 1, utf8_char, sizeof(utf8_char), NULL, NULL)) == 0)
				fatal("character conversion failed");

			/* append to output buffer if the characters fit */
			if (current_index + utf8_read >= outBufLen - 1) break;
			memcpy(&outBuf[current_index], utf8_char, utf8_read);
			current_index += utf8_read;

			if(flags & RPP_ECHO_ON)
				wprintf_s(L"%c", ch);
		}
	}

	outBuf[current_index] = '\0';
	_cputs("\n");

	return outBuf;
}

void 
invalid_parameter_handler(const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t pReserved)
{	
	debug3("Invalid parameter in function: %ls. File: %ls Line: %d.", function, file, line);
	debug3("Expression: %s", expression);
}

void
to_lower_case(char *s)
{
	for (; *s; s++)
		*s = tolower((u_char)*s);
}

void 
to_wlower_case(wchar_t *s)
{
	for (; *s; s++)
		*s = towlower(*s);
}

static int
get_final_mode(int allow_mode, int deny_mode)
{	
	// If deny permissions are not specified then return allow permissions.
	if (!deny_mode) return allow_mode;

	// If allow permissions are not specified then return allow permissions (0).
	if (!allow_mode) return allow_mode;
	
	if(deny_mode & S_IROTH)
		allow_mode = allow_mode & ~S_IROTH;

	if (deny_mode & S_IWOTH)
		allow_mode = allow_mode & ~S_IWOTH;

	if (deny_mode & S_IXOTH)
		allow_mode = allow_mode & ~S_IXOTH;

	return allow_mode;
}

int
get_others_file_permissions(wchar_t * file_name, int isReadOnlyFile)
{
	PSECURITY_DESCRIPTOR pSD = NULL;
	PSID owner_sid = NULL, current_trustee_sid = NULL;
	PACL dacl = NULL;
	DWORD error_code = ERROR_SUCCESS;
	BOOL is_valid_sid = FALSE, is_valid_acl = FALSE;
	int ret = 0, allow_mode_world = 0, allow_mode_auth_users = 0, deny_mode_world = 0, deny_mode_auth_users = 0;
	wchar_t *w_sid = NULL;

	/*Get the owner sid of the file.*/
	if ((error_code = GetNamedSecurityInfoW(file_name, SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		&owner_sid, NULL, &dacl, NULL, &pSD)) != ERROR_SUCCESS) {
		debug3("failed to retrieve the owner sid and dacl of file: %ls with error code: %d", file_name, error_code);
		goto cleanup;
	}

	if (((is_valid_sid = IsValidSid(owner_sid)) == FALSE) || dacl == NULL ||
		((is_valid_acl = IsValidAcl(dacl)) == FALSE)) {
		debug3("IsValidSid: %d; NULL Acl: %d; IsValidAcl: %d", is_valid_sid, dacl == NULL, is_valid_acl);
		goto cleanup;
	}

	for (DWORD i = 0; i < dacl->AceCount; i++) {
		PVOID current_ace = NULL;
		PACE_HEADER current_aceHeader = NULL;
		ACCESS_MASK current_access_mask = 0;
		int mode_tmp = 0;
		if (!GetAce(dacl, i, &current_ace)) {
			debug3("GetAce() failed");
			goto cleanup;
		}

		current_aceHeader = (PACE_HEADER)current_ace;
		/* only interested in Allow ACE */
		if (current_aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
			PACCESS_ALLOWED_ACE pAllowedAce = (PACCESS_ALLOWED_ACE)current_ace;
			current_trustee_sid = &(pAllowedAce->SidStart);
			current_access_mask = pAllowedAce->Mask;
		} else if (current_aceHeader->AceType == ACCESS_DENIED_ACE_TYPE) {
			PACCESS_DENIED_ACE pDeniedAce = (PACCESS_DENIED_ACE)current_ace;
			current_trustee_sid = &(pDeniedAce->SidStart);
			current_access_mask = pDeniedAce->Mask;
		} else continue;
		
		if (!(IsWellKnownSid(current_trustee_sid, WinWorldSid) || 
		    IsWellKnownSid(current_trustee_sid, WinAuthenticatedUserSid)))
			continue;
		
		if ((current_access_mask & READ_PERMISSIONS) == READ_PERMISSIONS)
			mode_tmp |= S_IROTH;

		if (!isReadOnlyFile && ((current_access_mask & WRITE_PERMISSIONS) == WRITE_PERMISSIONS))
			mode_tmp |= S_IWOTH;

		if ((current_access_mask & EXECUTE_PERMISSIONS) == EXECUTE_PERMISSIONS)
			mode_tmp |= S_IXOTH;

		if (IsWellKnownSid(current_trustee_sid, WinWorldSid)) {
			if(current_aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
				allow_mode_world |= mode_tmp;
			else
				deny_mode_world |= mode_tmp;
		} else if (IsWellKnownSid(current_trustee_sid, WinAuthenticatedUserSid)) {
			if (current_aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
				allow_mode_auth_users |= mode_tmp;
			else
				deny_mode_auth_users |= mode_tmp;
		}
	}
	
	allow_mode_world = get_final_mode(allow_mode_world, deny_mode_world);
	allow_mode_auth_users = get_final_mode(allow_mode_auth_users, deny_mode_auth_users);

	ret = allow_mode_world ? allow_mode_world : allow_mode_auth_users;
cleanup:
	if (pSD)
		LocalFree(pSD);
	return ret;
}

/* Windows absolute paths - \abc, /abc, c:\abc, c:/abc, __PROGRAMDATA__\openssh\sshd_config */
int
is_absolute_path(const char *path)
{
	int retVal = 0;
	if(*path == '\"' || *path == '\'') /* skip double quote if path is "c:\abc" */
		path++;

	if (*path == '/' || *path == '\\' || (*path != '\0' && __isascii(*path) && isalpha(*path) && path[1] == ':') ||
	    ((strlen(path) >= strlen(PROGRAM_DATA)) && (memcmp(path, PROGRAM_DATA, strlen(PROGRAM_DATA)) == 0)))
		retVal = 1;

	return retVal;
}

/* return -1 - in case of failure, 0 - success */
int
create_directory_withsddl(wchar_t *path_w, wchar_t *sddl_w)
{
	if (GetFileAttributesW(path_w) == INVALID_FILE_ATTRIBUTES) {
		PSECURITY_DESCRIPTOR pSD = NULL;
		SECURITY_ATTRIBUTES sa;
		memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle = FALSE;

		if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl_w, SDDL_REVISION, &pSD, NULL) == FALSE) {
			error("ConvertStringSecurityDescriptorToSecurityDescriptorW failed with error code %d", GetLastError());
			return -1;
		}

		if (IsValidSecurityDescriptor(pSD) == FALSE) {
			error("IsValidSecurityDescriptor return FALSE");
			return -1;
		}

		sa.lpSecurityDescriptor = pSD;
		if (!CreateDirectoryW(path_w, &sa)) {
			error("Failed to create directory:%ls error:%d", path_w, GetLastError());
			return -1;
		}
	}

	return 0;
}

/* return -1 - in case of failure, 0 - success */
int
copy_file(char *source, char *destination)
{
	if (!source || !destination) return 0;

	struct stat st;
	if ((stat(source, &st) >= 0) && (stat(destination, &st) < 0)) {
		wchar_t *source_w = utf8_to_utf16(source);
		if (!source_w) {
			error("%s utf8_to_utf16() has failed to convert string:%s", __func__, source_w);
			return -1;
		}

		wchar_t *destination_w = utf8_to_utf16(destination);
		if (!destination_w) {
			error("%s utf8_to_utf16() has failed to convert string:%s", __func__, destination_w);
			return -1;
		}

		if (!CopyFileW(source_w, destination_w, FALSE)) {
			error("Failed to copy %ls to %ls, error:%d", source_w, destination_w, GetLastError());
			return -1;
		}
	}

	return 0;
}

struct tm *
localtime_r(const time_t *timep, struct tm *result)
{
	return localtime_s(result, timep) == 0 ? result : NULL;
}

void
freezero(void *ptr, size_t sz)
{
	if (ptr == NULL)
		return;
	explicit_bzero(ptr, sz);
	free(ptr);
}

int 
setenv(const char *name, const char *value, int rewrite)
{
	errno_t result = 0;

	/* If rewrite is 0, then set only if the variable name doesn't already exist in environment */
	if (!rewrite) {
		char *envValue = NULL;
		size_t len = 0;
		_dupenv_s(&envValue, &len, name);

		if (envValue)
			return result; /* return success (as per setenv manpage) */
	}

	if (!(result = _putenv_s(name, value)))
		return 0;
	else {
		error("failed to set the environment variable:%s to value:%s, error:%d", name, value, result);
		errno = result;
		return -1;
	}
}

int
chroot(const char *path)
{
	char cwd[PATH_MAX];

	if (strcmp(path, ".") == 0) {
		if (w32_getcwd(cwd, PATH_MAX) == NULL)
			return -1;
		path = (const char *)cwd;
	} else if (*(path + 1) != ':') {
		errno = ENOTSUP;
		error("chroot only supports absolute paths");
		return -1;
	} else {
		/* TODO - ensure path exists and is a directory */
	}

	if ((chroot_path = _strdup(path)) == NULL) {
		errno = ENOMEM;
		return -1;
	}

	to_lower_case(chroot_path);
	convertToBackslash(chroot_path);

	/* strip trailing \ */
	if (chroot_path[strlen(chroot_path) - 1] == '\\')
		chroot_path[strlen(chroot_path) - 1] = '\0';

	chroot_path_len = (int) strlen(chroot_path);

	if ((chroot_pathw = utf8_to_utf16(chroot_path)) == NULL) {
		errno = ENOMEM;
		return -1;
	}

	/* TODO - set the env variable just in time in a posix_spawn_chroot like API */
#define POSIX_CHROOTW L"c28fc6f98a2c44abbbd89d6a3037d0d9_POSIX_CHROOT"
	_wputenv_s(POSIX_CHROOTW, chroot_pathw);

	return 0;
}

/*
 * Am I running as SYSTEM ?
 * a security sensitive call - fatal exits if it cannot definitively conclude 
 */
int 
am_system()
{
	HANDLE proc_token = NULL;
	DWORD info_len;
	TOKEN_USER* info = NULL;
	static int running_as_system = -1;

	if (running_as_system != -1)
		return running_as_system;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &proc_token) == FALSE ||
		GetTokenInformation(proc_token, TokenUser, NULL, 0, &info_len) == TRUE ||
		(info = (TOKEN_USER*)malloc(info_len)) == NULL ||
		GetTokenInformation(proc_token, TokenUser, info, info_len, &info_len) == FALSE)
		fatal("unable to know if I am running as system");

	if (IsWellKnownSid(info->User.Sid, WinLocalSystemSid))
		running_as_system = 1;
	else
		running_as_system = 0;

	CloseHandle(proc_token);
	free(info);
	return running_as_system;
}

/* 
 * returns SID of user/group or current user if (user = NULL) 
 * caller should free() return value
 */
PSID
get_sid(const char* name)
{
	HANDLE token = NULL;
	TOKEN_USER* info = NULL;
	DWORD info_len = 0;
	PSID ret = NULL, psid = NULL;
	wchar_t* name_utf16 = NULL;

	if (name) {
		DWORD sid_len = 0;
		SID_NAME_USE n_use;
		WCHAR dom[DNLEN + 1] = L"";
		DWORD dom_len = DNLEN + 1;

		if ((name_utf16 = utf8_to_utf16(name)) == NULL)
			goto cleanup;

		LookupAccountNameW(NULL, name_utf16, NULL, &sid_len, dom, &dom_len, &n_use);

		if (sid_len == 0) {
			errno = errno_from_Win32LastError();
			goto cleanup;
		}

		if ((psid = malloc(sid_len)) == NULL) {
			errno = ENOMEM;
			goto cleanup;
		}

		if (!LookupAccountNameW(NULL, name_utf16, psid, &sid_len, dom, &dom_len, &n_use)) {
			errno = errno_from_Win32LastError();
			goto cleanup;
		}
	}
	else {
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE ||
		    GetTokenInformation(token, TokenUser, NULL, 0, &info_len) == TRUE) {
			errno = EOTHER;
			goto cleanup;
		}

		if ((info = (TOKEN_USER*)malloc(info_len)) == NULL) {
			errno = ENOMEM;
			goto cleanup;
		}

		if (GetTokenInformation(token, TokenUser, info, info_len, &info_len) == FALSE) {
			errno = errno_from_Win32LastError();
			goto cleanup;
		}

		if ((psid = malloc(GetLengthSid(info->User.Sid))) == NULL) {
			errno = ENOMEM;
			goto cleanup;
		}

		if (!CopySid(GetLengthSid(info->User.Sid), psid, info->User.Sid)) {
			errno = errno_from_Win32LastError();
			goto cleanup;
		}
	}

	ret = psid;
	psid = NULL;
cleanup:

	if (token)
		CloseHandle(token);
	if (name_utf16)
		free(name_utf16);
	if (psid)
		free(psid);
	if (info)
		free(info);

	return ret;
}
/* Interpret scp and sftp executables*/
char *
build_exec_command(const char * command)
{
	enum cmd_type { CMD_OTHER, CMD_SFTP, CMD_SCP } command_type = CMD_OTHER;
	char *cmd_sp = NULL;
	int len = 0, command_len;
	const char *command_args = NULL;

	if (!command)
		return NULL;

	command_len = (int)strlen(command);
	/*TODO - replace numbers below with readable compile time operators*/
	if (command_len >= 13 && _memicmp(command, "internal-sftp", 13) == 0) {
		command_type = CMD_SFTP;
		command_args = command + 13;
	}
	else if (command_len >= 11 && _memicmp(command, "sftp-server", 11) == 0) {
		command_type = CMD_SFTP;

		/* account for possible .exe extension */
		if (command_len >= 15 && _memicmp(command + 11, ".exe", 4) == 0)
			command_args = command + 15;
		else
			command_args = command + 11;
	}
	else if (command_len >= 3 && _memicmp(command, "scp", 3) == 0) {
		command_type = CMD_SCP;

		/* account for possible .exe extension */
		if (command_len >= 7 && _memicmp(command + 3, ".exe", 4) == 0)
			command_args = command + 7;
		else
			command_args = command + 3;
	}

	len = command_len + 5; /* account for possible .exe addition and null term */
	if ((cmd_sp = malloc(len)) == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	memset(cmd_sp, '\0', len);
	if (command_type == CMD_SCP) {
		strcpy_s(cmd_sp, len, "scp.exe");
		strcat_s(cmd_sp, len, command_args);
	}
	else if (command_type == CMD_SFTP) {
		strcpy_s(cmd_sp, len, "sftp-server.exe");
		strcat_s(cmd_sp, len, command_args);
	}
	else
		strcpy_s(cmd_sp, len, command);
	return cmd_sp;
}

/*
* cmd is internally decoarated with a set of '"'
* to account for any spaces within the commandline
* the double quotes and backslash is escaped if needed
* this decoration is done only when additional arguments are passed in argv
*/
char *
build_commandline_string(const char* cmd, char *const argv[], BOOLEAN prepend_module_path)
{
	char *cmdline, *t, *tmp = NULL, *path = NULL, *ret = NULL;
	char * const *t1;
	DWORD cmdline_len = 0, path_len = 0;
	int add_module_path = 0;

	if (!cmd) {
		error("%s invalid argument cmd:%s", __func__, cmd);
		return NULL;
	}

	if (!(path = _strdup(cmd))) {
		error("failed to duplicate %s", cmd);
		return NULL;
	}

	path_len = (DWORD)strlen(path);

	if (is_bash_test_env()) {
		memset(path, 0, path_len + 1);
		bash_to_win_path(cmd, path, path_len + 1);
		path_len = (DWORD)strlen(path);
	}

	if (!is_absolute_path(path) && prepend_module_path)
		add_module_path = 1;

	/* compute total cmdline len*/
	if (add_module_path)
		cmdline_len += (DWORD)strlen(__progdir) + 1 + (DWORD)strlen(path) + 1 + 2;
	else
		cmdline_len += (DWORD)strlen(path) + 1 + 2;

	if (argv) {
		t1 = argv;
		while (*t1) {
			char *p = *t1++;
			for (int i = 0; i < (int)strlen(p); i++) {
				if (p[i] == '\\') {
					char * b = p + i;
					int additional_backslash = 0;
					int backslash_count = 0;
					/*
					Backslashes are interpreted literally, unless they immediately
					precede a double quotation mark.
					*/
					while (b != NULL && *b == '\\') {
						backslash_count++;
						b++;
						if (b != NULL &&  *b == '\"') {
							additional_backslash = 1;
							break;
						}
					}
					cmdline_len += backslash_count * (additional_backslash + 1);
					i += backslash_count - 1;
				}
				else if (p[i] == '\"')
					/* backslash will be added for every double quote.*/
					cmdline_len += 2;
				else
					cmdline_len++;
			}
			cmdline_len += 1 + 2; /*for "around cmd arg and traling space*/
		}
	}

	if ((cmdline = malloc(cmdline_len)) == NULL) {
		errno = ENOMEM;
		goto cleanup;
	}

	t = cmdline;

	*t++ = '\"';
	if (add_module_path) {
		/* add current module path to start if needed */
		memcpy(t, __progdir, strlen(__progdir));
		t += strlen(__progdir);
		*t++ = '\\';
	}

	if (path[0] != '\"') {
		/* If path is <executable_path> <arg> then we should add double quotes after <executable_path> i.e., "<executable_path>" <arg> should be passed to CreateProcess().
		* Example - If path is C:\cygwin64\bin\bash.exe /cygdrive/e/openssh-portable-latestw_all/openssh-portable/regress/scp-ssh-wrapper.sh then
		*           we should pass "C:\cygwin64\bin\bash.exe" /cygdrive/e/openssh-portable-latestw_all/openssh-portable/regress/scp-ssh-wrapper.sh
		*           to the CreateProcess() otherwise CreateProcess() will fail with error code 2.
		*/
		if (strstr(path, ".exe") && (tmp = strstr(strstr(path, ".exe"), " ")))
		{
			size_t tmp_pos = tmp - path;
			memcpy(t, path, tmp_pos);
			t += tmp_pos;
			*t++ = '\"';
			memcpy(t, tmp, strlen(path) - tmp_pos);
			t += (strlen(path) - tmp_pos);
		}
		else {
			memcpy(t, path, path_len);
			t += path_len;
			*t++ = '\"';
		}
	}
	else {
		/*path already contains "*/
		memcpy(t, path + 1, path_len - 1);
		t += path_len - 1;
	}

	*t = '\0';
	t = cmdline + strlen(cmdline);

	if (argv) {
		t1 = argv;
		while (*t1) {
			*t++ = ' ';
			char * p1 = *t1++;
			BOOL add_quotes = FALSE;
			/* leave as is if the command is surrounded by single quotes*/
			if (p1[0] != '\'')
				for (int i = 0; i < (int)strlen(p1); i++) {
					if (p1[i] == ' ') {
						add_quotes = TRUE;
						break;
					}
				}
			if (add_quotes)
				*t++ = '\"';
			for (int i = 0; i < (int)strlen(p1); i++) {
				if (p1[i] == '\\') {
					char * b = p1 + i;
					int additional_backslash = 0;
					int backslash_count = 0;
					/*
					* Backslashes are interpreted literally, unless they immediately
					* precede a double quotation mark.
					*/
					while (b != NULL && *b == '\\') {
						backslash_count++;
						b++;
						if (b != NULL && *b == '\"') {
							additional_backslash = 1;
							break;
						}
					}
					i += backslash_count - 1;
					int escaped_backslash_count = backslash_count * (additional_backslash + 1);
					while (escaped_backslash_count--)
						*t++ = '\\';
				}
				else if (p1[i] == '\"') {
					/* Add backslash for every double quote.*/
					*t++ = '\\';
					*t++ = '\"';
				}
				else
					*t++ = p1[i];
			}
			if (add_quotes)
				*t++ = '\"';
		}
	}
	*t = '\0';
	ret = cmdline;
	cmdline = NULL;
cleanup:
	if (path)
		free(path);
	if (cmdline)
		free(cmdline);
	return ret;
}

BOOL
is_bash_test_env()
{
	char *envValue = NULL;
	size_t len = 0;
	BOOL retVal = FALSE;
	_dupenv_s(&envValue, &len, "SSH_TEST_ENVIRONMENT");

	if ((NULL != envValue) && atoi(envValue))
		retVal = TRUE;

	if (envValue)
		free(envValue);

	return retVal;
}

int
bash_to_win_path(const char *in, char *out, const size_t out_len)
{
	int retVal = 0;
	const size_t cygwin_path_prefix_len = strlen(CYGWIN_PATH_PREFIX);
	memset(out, 0, out_len);
	if (_strnicmp(in, CYGWIN_PATH_PREFIX, cygwin_path_prefix_len) == 0) {
		out[0] = in[cygwin_path_prefix_len];
		out[1] = ':';
		strcat_s(out, out_len, &in[cygwin_path_prefix_len + 1]);
		retVal = 1;
	} else
		strcpy_s(out, out_len, in);

	return retVal;
}

int
getpeereid(int s, uid_t *euid, gid_t *egid)
{
	verbose("%s is not supported", __func__);
	errno = ENOTSUP;
	return -1;
}

int
getrrsetbyname(const char *hostname, unsigned int rdclass,
	unsigned int rdtype, unsigned int flags,
	struct rrsetinfo **res)
{
	verbose("%s is not supported", __func__);
	errno = ENOTSUP;
	return -1;
}

int 
fnmatch(const char *pattern, const char *string, int flags)
{
	int r = -1;
	wchar_t *pw = NULL, *sw = NULL;

	if (flags) {
		verbose("%s is not supported with flags", __func__);
		goto done;
	}

	pw = utf8_to_utf16(pattern);
	sw = utf8_to_utf16(string);
	if (!pw || !sw)
		goto done;
	convertToBackslashW(pw);
	convertToBackslashW(sw);
	if (PathMatchSpecW(sw, pw))
		r = 0;
done:
	if (pw)
		free(pw);
	if (sw)
		free(sw);
	return r;
}

void
freerrset(struct rrsetinfo *rrset)
{
	verbose("%s is not supported", __func__);
	return;
}

void
debug_assert_internal()
{
	/* debug break on non-release builds */
#ifndef NDEBUG
	DebugBreak();
#endif
}

char
*crypt(const char *key, const char *salt)
{
	verbose("%s is not supported", __func__);
	errno = ENOTSUP;
	return NULL;
}

int
w32_system(const char *command)
{
	int ret = -1;
	wchar_t *command_w = NULL;

	if (!command) {
		errno = ENOTSUP;
		goto cleanup;
	}

	if ((command_w = utf8_to_utf16(command)) == NULL)
		goto cleanup;

	ret = _wsystem(command_w);

cleanup:
	if (command_w)
		free(command_w);

	return ret;
}

char *
strrstr(const char *inStr, const char *pattern)
{
	char *tmp = NULL, *last = NULL;
	tmp = (char *) inStr;
	while(tmp = strstr(tmp, pattern))
		last = tmp++;

	return last;
}