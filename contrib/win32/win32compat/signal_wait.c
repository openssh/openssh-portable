/*
* Author: Bryan Berns <berns@uwalumni.com>
*
* Partial replacement for WaitForMultipleObjectsEx that handles more than 64
* objects.  This is tuned for OpenSSH use in (no need for 'wait-all' scenarios).
* This is only safe to use for objects whose transitional state is not
* automatically lost just by calling a WaitForMultipleObjects* or
* WaitForSingleObjects*.
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

#include "signal_internal.h"

typedef struct _wait_for_multiple_objects_struct {
	/* synchronization management */
	HANDLE thread_handle;
	HANDLE wait_event;

	/* native function parameters input and output */
	DWORD num_handles;
	const HANDLE * handles;
	DWORD return_value;
}
wait_for_multiple_objects_struct;

unsigned __stdcall
wait_for_multiple_objects_thread(LPVOID lpParam)
{
	wait_for_multiple_objects_struct *waitstruct = 
		(wait_for_multiple_objects_struct *) lpParam;

	/* wait for bin to complete -- this is alertable for our interrupt cleanup routine */
	waitstruct->return_value = WaitForMultipleObjectsEx(waitstruct->num_handles,
		waitstruct->handles, FALSE, INFINITE, TRUE);

	/* notify the main thread that an event was found */
	SetEvent(waitstruct->wait_event);

	return TRUE;
}

VOID CALLBACK
wait_for_multiple_objects_interrupter(_In_ ULONG_PTR dwParam)
{
	/* we must explicitly exit the thread since the thread could have been received
	 * the alert prior to the thread running in which case it is acknowledged when
	 * the threads starts running instead of when it is waiting at
	 * WaitForMultipleObjectsEx */
	_endthreadex(0);
}

DWORD
wait_for_multiple_objects_enhanced(_In_ DWORD  nCount, _In_ const HANDLE *lpHandles,
	_In_ DWORD dwMilliseconds, _In_ BOOL bAlertable)
{
	/* number of separate bins / threads required to monitor execution */
	const DWORD bin_size = MAXIMUM_WAIT_OBJECTS;
	const DWORD bins_total = (nCount - 1) / bin_size + 1;
	
	DWORD return_value = WAIT_FAILED_ENHANCED;
	HANDLE wait_event = NULL;
	wait_for_multiple_objects_struct wait_bins[(MAXIMUM_WAIT_OBJECTS_ENHANCED - 1) / MAXIMUM_WAIT_OBJECTS + 1] = { 0 };
	DWORD wait_ret;

	/* protect against too many events */
	if (nCount > MAXIMUM_WAIT_OBJECTS_ENHANCED)
	{
		return WAIT_FAILED_ENHANCED;
	}

	/* in the event that no events are passed and alterable, just do a sleep and
	 * and wait for wakeup call.  This differs from the WaitForMultipleObjectsEx
	 * call which would return an error if no events are passed to the function. */
	if (nCount == 0 && bAlertable)
	{
		DWORD wait_ret = SleepEx(dwMilliseconds, TRUE);
		if (wait_ret == 0)
			return WAIT_TIMEOUT_ENHANCED;
		else if (wait_ret == WAIT_IO_COMPLETION) 
			return WAIT_IO_COMPLETION_ENHANCED;
		else
			return WAIT_FAILED_ENHANCED;
	}
	
	/* if less than the normal maximum then just use the built-in function
	 * to avoid the overhead of another thread */
	if (nCount <= MAXIMUM_WAIT_OBJECTS) {

		DWORD wait_ret = WaitForMultipleObjectsEx(nCount, lpHandles,
			FALSE, dwMilliseconds, bAlertable);

		if (wait_ret == WAIT_IO_COMPLETION) return WAIT_IO_COMPLETION_ENHANCED;
		if (wait_ret == WAIT_TIMEOUT) return WAIT_TIMEOUT_ENHANCED;

		/* translate normal offset to enhanced offset for abandoned threads */
		if (wait_ret >= WAIT_ABANDONED_0 &&
			wait_ret < WAIT_ABANDONED_0 + MAXIMUM_WAIT_OBJECTS) {
			return WAIT_ABANDONED_0_ENHANCED + (wait_ret - WAIT_ABANDONED_0);
		}

		/* translate normal offset to enhanced offset for signaled threads */
		if (wait_ret >= WAIT_OBJECT_0 &&
			wait_ret < WAIT_OBJECT_0 + MAXIMUM_WAIT_OBJECTS) {
			return WAIT_OBJECT_0_ENHANCED + (wait_ret - WAIT_OBJECT_0);
		}

		return WAIT_FAILED_ENHANCED;
	}

	/* setup synchronization event to flag when the main thread should wake up */
	wait_event = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (wait_event == NULL) {
		goto cleanup;
	}

	/* initialize each thread that handles up to MAXIMUM_WAIT_OBJECTS each */
	for (DWORD bin = 0; bin < bins_total; bin++) {

		const int handles_processed = bin * bin_size;

		wait_bins[bin].return_value = WAIT_FAILED - 1;
		wait_bins[bin].wait_event = wait_event;
		wait_bins[bin].handles = &(lpHandles[handles_processed]);
		wait_bins[bin].num_handles = min(nCount - handles_processed, bin_size);

		/* create a thread for this bin */
		if ((wait_bins[bin].thread_handle = (HANDLE) _beginthreadex(NULL,
			2048, wait_for_multiple_objects_thread,
			(LPVOID) &(wait_bins[bin]), 0, NULL)) == NULL) {
			goto cleanup;
		}
	}

	/* wait for at least one thread to return; this will indicate that return
	 * value will have been set in our bin array */
	wait_ret = WaitForSingleObjectEx(wait_event, dwMilliseconds, bAlertable);

	/* if io alert just skip to end */
	if (wait_ret == WAIT_IO_COMPLETION) {
		return_value = WAIT_IO_COMPLETION_ENHANCED;
		goto cleanup;
	}

	/* if timeout just skip to end */
	if (wait_ret == WAIT_TIMEOUT) {
		return_value = WAIT_TIMEOUT_ENHANCED;
		goto cleanup;
	}

	/* unexpected output result */
	if (wait_ret != WAIT_OBJECT_0) {
		return_value = WAIT_FAILED_ENHANCED;
		goto cleanup;
	}

	/* only looking for one object events */
	for (DWORD bin = 0; bin < bins_total; bin++) {

		/* skip bins that have have the default, unprocessed status */
		if (wait_bins[bin].return_value == WAIT_FAILED - 1)
			continue;

		/* return failure if a bin has been processed but returned an
		 * invalid or unexpected status */
		if (wait_bins[bin].return_value == WAIT_FAILED ||
			wait_bins[bin].return_value == WAIT_IO_COMPLETION ||
			wait_bins[bin].return_value == WAIT_TIMEOUT)
		{
			return_value = WAIT_FAILED_ENHANCED;
			break;
		}

		/* translate normal offset to enhanced offset for abandoned threads */
		if (wait_bins[bin].return_value >= WAIT_ABANDONED_0 &&
			wait_bins[bin].return_value < WAIT_ABANDONED_0 + wait_bins[bin].num_handles) {
			return_value = WAIT_ABANDONED_0_ENHANCED +
				bin * bin_size + (wait_bins[bin].return_value - WAIT_ABANDONED_0);
			break;
		}

		/* translate normal offset to enhanced offset for signaled threads */
		if (wait_bins[bin].return_value >= WAIT_OBJECT_0 &&
			wait_bins[bin].return_value < WAIT_OBJECT_0 + wait_bins[bin].num_handles) {
			return_value = WAIT_OBJECT_0_ENHANCED +
				bin * bin_size + (wait_bins[bin].return_value - WAIT_OBJECT_0);
			break;
		}
	}

cleanup:

	/* interrupt any outstanding threads */
	for (DWORD bin = 0; bin < bins_total; bin++) {
		if (wait_bins[bin].thread_handle != NULL) {

			/* send each thread that is still waiting a signal to wake up;
			 * if the thread in not waiting and still has not fully
			 * finished executing then it will just ignore the signal */
			if (wait_bins[bin].return_value == (WAIT_FAILED - 1)) {
				QueueUserAPC(wait_for_multiple_objects_interrupter,
					wait_bins[bin].thread_handle, (ULONG_PTR)NULL);
			}

			/* we must wait for these threads to complete so we can
			 * safely cleanup the shared resources */
			WaitForSingleObject(wait_bins[bin].thread_handle, INFINITE);
			CloseHandle(wait_bins[bin].thread_handle);
		}
	}

	if (wait_event)
		CloseHandle(wait_event);
	return return_value;
}
