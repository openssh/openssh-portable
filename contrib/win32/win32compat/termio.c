/*
 * Author: Manoj Ampalam <manojamp@microsoft.com>
 *  read() and write() on tty using worker threads to handle 
 *  synchronous Windows Console IO
 * 
 * Author: Ray Hayes <ray.hayes@microsoft.com>
 *  TTY/PTY support added by capturing all terminal input events
 *
 * Author: Balu <bagajjal@microsoft.com>
 *  Misc fixes and code cleanup
 *
 * Author: Manoj Ampalam <manojamp@microsoft.com>
 *  Extended support to other Windows IO that does not support 
 *  overlapped IO. Ex. pipe handles returned by CreatePipe()
 * 
 * Copyright (c) 2017 Microsoft Corp.
 * All rights reserved
 *
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
#include "w32fd.h"
#include "tncon.h"
#include "inc\utf.h"
#include "debug.h"
#include "tnnet.h"

#define TERM_IO_BUF_SIZE 2048

extern int in_raw_mode;

struct io_status {
	DWORD to_transfer;
	DWORD transferred;
	DWORD error;
};
static struct io_status read_status, write_status;

/* APC that gets queued on main thread when a sync Read completes on worker thread */
static VOID CALLBACK
ReadAPCProc(_In_ ULONG_PTR dwParam)
{
	struct w32_io* pio = (struct w32_io*)dwParam;
	debug5("TermRead CB - io:%p, bytes: %d, pending: %d, error: %d", pio, read_status.transferred,
		pio->read_details.pending, read_status.error);
	pio->read_details.error = read_status.error;
	pio->read_details.remaining = read_status.transferred;
	pio->read_details.completed = 0;
	pio->read_details.pending = FALSE;
	WaitForSingleObject(pio->read_overlapped.hEvent, INFINITE);
	CloseHandle(pio->read_overlapped.hEvent);
	pio->read_overlapped.hEvent = 0;
}

/* Read worker thread */
static DWORD WINAPI
ReadThread(_In_ LPVOID lpParameter)
{
	int nBytesReturned = 0;
	struct w32_io* pio = (struct w32_io*)lpParameter;

	debug5("TermRead thread, io:%p", pio);
	memset(&read_status, 0, sizeof(read_status));
	if (FILETYPE(pio) == FILE_TYPE_CHAR) {
		while (nBytesReturned == 0) {
			nBytesReturned = ReadConsoleForTermEmul(WINHANDLE(pio),
				pio->read_details.buf, pio->read_details.buf_size);
		}
		read_status.transferred = nBytesReturned;
	} else {
		if (!ReadFile(WINHANDLE(pio), pio->read_details.buf,
		    pio->read_details.buf_size, &read_status.transferred, NULL)) {
			read_status.error = GetLastError();
			debug("ReadThread - ReadFile failed %d, io:%p", GetLastError(), pio);
		}
	}
	if (0 == QueueUserAPC(ReadAPCProc, main_thread, (ULONG_PTR)pio)) {
		debug3("TermRead thread - ERROR QueueUserAPC failed %d, io:%p", GetLastError(), pio);
		pio->read_details.pending = FALSE;
		pio->read_details.error = GetLastError();
		DebugBreak();
	}

	return 0;
}

/* Initiates read on tty */
int
syncio_initiate_read(struct w32_io* pio)
{
	HANDLE read_thread;

	debug5("syncio_initiate_read io:%p", pio);
	if (pio->read_details.buf_size == 0) {
		pio->read_details.buf = malloc(TERM_IO_BUF_SIZE);
		if (pio->read_details.buf == NULL) {
			errno = ENOMEM;
			return -1;
		}
		pio->read_details.buf_size = TERM_IO_BUF_SIZE;
	}

	read_thread = CreateThread(NULL, 0, ReadThread, pio, 0, NULL);
	if (read_thread == NULL) {
		errno = errno_from_Win32Error(GetLastError());
		debug3("TermRead initiate - ERROR CreateThread %d, io:%p", GetLastError(), pio);
		return -1;
	}

	pio->read_overlapped.hEvent = read_thread;
	pio->read_details.pending = TRUE;
	return 0;
}

/* APC that gets queued on main thread when a sync Write completes on worker thread */
static VOID CALLBACK 
WriteAPCProc(_In_ ULONG_PTR dwParam)
{
	struct w32_io* pio = (struct w32_io*)dwParam;
	debug5("TermWrite CB - io:%p, bytes: %d, pending: %d, error: %d", pio, write_status.transferred,
		pio->write_details.pending, write_status.error);
	pio->write_details.error = write_status.error;
	pio->write_details.remaining -= write_status.transferred;
	/* TODO- assert that reamining is 0 by now */
	pio->write_details.completed = 0;
	pio->write_details.pending = FALSE;
	WaitForSingleObject(pio->write_overlapped.hEvent, INFINITE);
	CloseHandle(pio->write_overlapped.hEvent);
	pio->write_overlapped.hEvent = 0;
}


/* Write worker thread */
static DWORD WINAPI 
WriteThread(_In_ LPVOID lpParameter)
{
	struct w32_io* pio = (struct w32_io*)lpParameter;
	char *respbuf = NULL;
	size_t resplen = 0;	
	debug5("TermWrite thread, io:%p", pio);

	if (FILETYPE(pio) == FILE_TYPE_CHAR) {
		pio->write_details.buf[write_status.to_transfer] = '\0';
		if (0 == in_raw_mode) {
			wchar_t* t = utf8_to_utf16(pio->write_details.buf);
			WriteConsoleW(WINHANDLE(pio), t, wcslen(t), 0, 0);
			free(t);		
		} else {
			processBuffer(WINHANDLE(pio), pio->write_details.buf, write_status.to_transfer, &respbuf, &resplen);
			/* TODO - respbuf is not null in some cases, this needs to be returned back via read stream */
		}
		write_status.transferred = write_status.to_transfer;
	} else {
		if (!WriteFile(WINHANDLE(pio), pio->write_details.buf, write_status.to_transfer,
		    &write_status.transferred, NULL)) {
			write_status.error = GetLastError();
			debug("WriteThread - ReadFile WriteFile %d, io:%p", GetLastError(), pio);
		}
	}

	
	if (0 == QueueUserAPC(WriteAPCProc, main_thread, (ULONG_PTR)pio)) {
		debug3("TermWrite thread - ERROR QueueUserAPC failed %d, io:%p", GetLastError(), pio);
		pio->write_details.pending = FALSE;
		pio->write_details.error = GetLastError();
		DebugBreak();
	}

	return 0;
}

/* Initiates write on tty */
int
syncio_initiate_write(struct w32_io* pio, DWORD num_bytes)
{
	HANDLE write_thread;
	debug5("TermWrite initiate io:%p", pio);
	memset(&write_status, 0, sizeof(write_status));
	write_status.to_transfer = num_bytes;
	write_thread = CreateThread(NULL, 0, WriteThread, pio, 0, NULL);
	if (write_thread == NULL) {
		errno = errno_from_Win32Error(GetLastError());
		debug3("TermWrite initiate - ERROR CreateThread %d, io:%p", GetLastError(), pio);
		return -1;
	}

	pio->write_overlapped.hEvent = write_thread;
	pio->write_details.pending = TRUE;
	return 0;
}

/* tty close */
int 
syncio_close(struct w32_io* pio)
{
	debug4("syncio_close - pio:%p", pio);
	HANDLE h;
	CancelIoEx(WINHANDLE(pio), NULL);

	/* If io is pending, let worker threads exit. */
	if (pio->read_details.pending) {
		/* For console - the read thread is blocked so terminate it. */
		if (FILETYPE(pio) == FILE_TYPE_CHAR)
			TerminateThread(pio->read_overlapped.hEvent, 0);
		else
			WaitForSingleObject(pio->read_overlapped.hEvent, INFINITE);
	}
	if (pio->write_details.pending)
		WaitForSingleObject(pio->write_overlapped.hEvent, INFINITE);
	/* drain queued APCs */
	SleepEx(0, TRUE);
	CloseHandle(WINHANDLE(pio));
	/* free up if non stdio */
	if (!IS_STDIO(pio)) {
		if (pio->read_details.buf)
			free(pio->read_details.buf);
		if (pio->write_details.buf)
			free(pio->write_details.buf);
		free(pio);
	}
	return 0;
}
