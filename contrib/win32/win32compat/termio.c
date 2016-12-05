#include <Windows.h>
#include "w32fd.h"
#include "tncon.h"
#include "inc/defs.h"

#define TERM_IO_BUF_SIZE 2048

struct io_status {
	DWORD to_transfer;
	DWORD transferred;
	DWORD error;
};

static struct io_status read_status, write_status;

static VOID CALLBACK ReadAPCProc(
	_In_ ULONG_PTR dwParam
	) {
	struct w32_io* pio = (struct w32_io*)dwParam;
	debug3("TermRead CB - io:%p, bytes: %d, pending: %d, error: %d", pio, read_status.transferred,
		pio->read_details.pending, read_status.error);
	pio->read_details.error = read_status.error;
	pio->read_details.remaining = read_status.transferred;
	pio->read_details.completed = 0;
	pio->read_details.pending = FALSE;
	WaitForSingleObject(pio->read_overlapped.hEvent, INFINITE);
	CloseHandle(pio->read_overlapped.hEvent);
	pio->read_overlapped.hEvent = 0;
}

static DWORD WINAPI ReadThread(
	_In_ LPVOID lpParameter
	) {
	struct w32_io* pio = (struct w32_io*)lpParameter;
	debug3("TermRead thread, io:%p", pio);
	memset(&read_status, 0, sizeof(read_status));
	if (!ReadFile(WINHANDLE(pio), pio->read_details.buf, 
		pio->read_details.buf_size, &read_status.transferred, NULL)) {
		read_status.error = GetLastError();
		debug("TermRead thread - ReadFile failed %d, io:%p", GetLastError(), pio);
	}

	if (0 == QueueUserAPC(ReadAPCProc, main_thread, (ULONG_PTR)pio)) {
		debug("TermRead thread - ERROR QueueUserAPC failed %d, io:%p", GetLastError(), pio);
		pio->read_details.pending = FALSE;
		pio->read_details.error = GetLastError();
		DebugBreak();
	}
	return 0;
}

static DWORD WINAPI ReadConsoleThread(
    _In_ LPVOID lpParameter
) {
    int nBytesReturned = 0;

    struct w32_io* pio = (struct w32_io*)lpParameter;

    debug3("TermRead thread, io:%p", pio);
    memset(&read_status, 0, sizeof(read_status));
   
    while (nBytesReturned == 0) {
        nBytesReturned = ReadConsoleForTermEmul(WINHANDLE(pio),
            pio->read_details.buf, pio->read_details.buf_size);
    }

    read_status.transferred = nBytesReturned;

    if (0 == QueueUserAPC(ReadAPCProc, main_thread, (ULONG_PTR)pio)) {
        debug("TermRead thread - ERROR QueueUserAPC failed %d, io:%p", GetLastError(), pio);
        pio->read_details.pending = FALSE;
        pio->read_details.error = GetLastError();
        DebugBreak();
    }

    return 0;
}

int
termio_initiate_read(struct w32_io* pio) {
	HANDLE read_thread;

	debug3("TermRead initiate io:%p", pio);

	if (pio->read_details.buf_size == 0) {
		pio->read_details.buf = malloc(TERM_IO_BUF_SIZE);
		if (pio->read_details.buf == NULL) {
			errno = ENOMEM;
			return -1;
		}
		pio->read_details.buf_size = TERM_IO_BUF_SIZE;
	}

    read_thread = CreateThread(NULL, 0, ReadConsoleThread, pio, 0, NULL);
	if (read_thread == NULL) {
		errno = errno_from_Win32Error(GetLastError());
		debug("TermRead initiate - ERROR CreateThread %d, io:%p", GetLastError(), pio);
		return -1;
	}

	pio->read_overlapped.hEvent = read_thread;
	pio->read_details.pending = TRUE;
	return 0;
}

static VOID CALLBACK WriteAPCProc(
	_In_ ULONG_PTR dwParam
	) {
	struct w32_io* pio = (struct w32_io*)dwParam;
	debug3("TermWrite CB - io:%p, bytes: %d, pending: %d, error: %d", pio, write_status.transferred,
		pio->write_details.pending, write_status.error);
	pio->write_details.error = write_status.error;
	pio->write_details.remaining -= write_status.transferred;
	/*TODO- assert that reamining is 0 by now*/
	pio->write_details.completed = 0;
	pio->write_details.pending = FALSE;
	WaitForSingleObject(pio->write_overlapped.hEvent, INFINITE);
	CloseHandle(pio->write_overlapped.hEvent);
	pio->write_overlapped.hEvent = 0;
}

static DWORD WINAPI WriteThread(
	_In_ LPVOID lpParameter
	) {
	struct w32_io* pio = (struct w32_io*)lpParameter;
        char *respbuf = NULL;
        size_t resplen = 0;
        DWORD dwSavedAttributes = ENABLE_PROCESSED_INPUT;
	debug3("TermWrite thread, io:%p", pio);
	
        /* decide to call parsing engine or directly write to console
         * doing the following trick to decide -
         * if console in handle is set to process Ctrl+C, then it is likely
         * serving a PTY enabled session 
         */ 
        GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &dwSavedAttributes);
        if (dwSavedAttributes & ENABLE_PROCESSED_INPUT) {
                if (!WriteFile(WINHANDLE(pio), pio->write_details.buf, write_status.to_transfer,
                        &write_status.transferred, NULL)) {
                        write_status.error = GetLastError();
                        debug("TermWrite thread - WriteFile failed %d, io:%p", GetLastError(), pio);
                }
        } else {

                telProcessNetwork(pio->write_details.buf, write_status.to_transfer, &respbuf, &resplen);
                /*TODO - respbuf is not null in some cases, this needs to be returned back via read stream*/
                write_status.transferred = write_status.to_transfer;
        }

	if (0 == QueueUserAPC(WriteAPCProc, main_thread, (ULONG_PTR)pio)) {
		debug("TermWrite thread - ERROR QueueUserAPC failed %d, io:%p", GetLastError(), pio);
		pio->write_details.pending = FALSE;
		pio->write_details.error = GetLastError();
		DebugBreak();
	}
	return 0;
}

int
termio_initiate_write(struct w32_io* pio, DWORD num_bytes) {
	HANDLE write_thread;

	debug3("TermWrite initiate io:%p", pio);
	memset(&write_status, 0, sizeof(write_status));
	write_status.to_transfer = num_bytes;
	write_thread = CreateThread(NULL, 0, WriteThread, pio, 0, NULL);
	if (write_thread == NULL) {
		errno = errno_from_Win32Error(GetLastError());
		debug("TermWrite initiate - ERROR CreateThread %d, io:%p", GetLastError(), pio);
		return -1;
	}

	pio->write_overlapped.hEvent = write_thread;
	pio->write_details.pending = TRUE;
	return 0;
}


int termio_close(struct w32_io* pio) {
	debug2("termio_close - pio:%p", pio);
	HANDLE h;

	CancelIoEx(WINHANDLE(pio), NULL);
	/* If io is pending, let write worker threads exit. The read thread is blocked so terminate it.*/
    if (pio->read_details.pending)
        TerminateThread(pio->read_overlapped.hEvent, 0);
	if (pio->write_details.pending)
		WaitForSingleObject(pio->write_overlapped.hEvent, INFINITE);
	/* drain queued APCs */
	SleepEx(0, TRUE);
	if (pio->type != STD_IO_FD) {//STD handles are never explicitly closed
		CloseHandle(WINHANDLE(pio));

		if (pio->read_details.buf)
			free(pio->read_details.buf);

		if (pio->write_details.buf)
			free(pio->write_details.buf);

		free(pio);
	}
	return 0;
}
