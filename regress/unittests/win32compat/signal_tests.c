/*
* Author: Bryan Berns <berns@uwalumni.com>
*/

#include "includes.h"

#include "signal_internal.h"
#include "../test_helper/test_helper.h"
#include "tests.h"

VOID CALLBACK
signal_test_dummy_apc(_In_ ULONG_PTR dwParam)
{
	/* dummy */
}

DWORD WINAPI
signal_test_send_apc(LPVOID lpParam)
{
	HANDLE thread = (HANDLE)lpParam;
	Sleep(250);
	QueueUserAPC(signal_test_dummy_apc, thread, (ULONG_PTR)NULL);
	return TRUE;
}

DWORD WINAPI
signal_test_set_event(LPVOID lpParam)
{
	HANDLE hevent = (HANDLE)lpParam;
	Sleep(10);
	SetEvent(hevent);
	return TRUE;
}

DWORD WINAPI
signal_create_abandoned_object(LPVOID lpParam)
{
	*((HANDLE *)lpParam) = CreateMutex(NULL, TRUE, 0);
	return TRUE;
}

VOID TEST_RESOURCES(BOOL start)
{
	static DWORD initial_count = 0;
	if (start) GetProcessHandleCount(GetCurrentProcess(), &initial_count);
	else {
		DWORD final_count;
		GetProcessHandleCount(GetCurrentProcess(), &final_count);
		ASSERT_INT_EQ(initial_count, final_count);
	}
}

void
signal_test_wait_for_multiple_objects()
{
	/* shared test resources */
	HANDLE current_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
	HANDLE current_process = GetCurrentProcess();

	/* events for testing */
	HANDLE hObjects[300];
	const DWORD objects_size = ARRAYSIZE(hObjects);;
	for (int i = 0; i < objects_size; i++)
		hObjects[i] = CreateEvent(NULL, TRUE, FALSE, NULL);

	/* create abandoned mutex */
	HANDLE abandoned_mutux = NULL;
	HANDLE mutex_thread = CreateThread(NULL, 0, signal_create_abandoned_object, &abandoned_mutux, 0, NULL);
	WaitForSingleObject(mutex_thread, INFINITE);
	CloseHandle(mutex_thread);

	{
		TEST_START("Signal: APC wakeup with select event counts (WAIT_IO_COMPLETION_ENHANCED)");
		//TEST_RESOURCES(TRUE);

		for (int i = 0; i < objects_size; i++) ResetEvent(hObjects[i]);
		for (int i = 0; i < objects_size; i++) {
			DWORD select = i % MAXIMUM_WAIT_OBJECTS;
			if (select == 0 || select == 1 || select == MAXIMUM_WAIT_OBJECTS - 1 || select == MAXIMUM_WAIT_OBJECTS - 2) {
				CloseHandle(CreateThread(NULL, 0, signal_test_send_apc, current_thread, 0, NULL));
				DWORD ret = wait_for_multiple_objects_enhanced(i + 1, hObjects, 10000, TRUE);
				ASSERT_INT_EQ(ret, WAIT_IO_COMPLETION_ENHANCED);
			}
		}

		//TEST_RESOURCES(FALSE);
		TEST_DONE();
	}

	{
		TEST_START("Signal: Wait-any with one invalid event in positions 1-300 (WAIT_FAILED_ENHANCED)");
		//TEST_RESOURCES(TRUE);

		for (int i = 0; i < objects_size; i++) ResetEvent(hObjects[i]);
		for (int i = 0; i < objects_size; i++) {
			HANDLE event = hObjects[i];
			hObjects[i] = NULL;
			DWORD ret = wait_for_multiple_objects_enhanced(objects_size, hObjects, 10000, FALSE);
			ASSERT_INT_EQ(ret, WAIT_FAILED_ENHANCED);
			hObjects[i] = event;
		}

		//TEST_RESOURCES(FALSE);
		TEST_DONE();
	}

	{
		TEST_START("Signal: Wait-any with signaled event in positions 1-300 (WAIT_OBJECT_0_ENHANCED)");
		//TEST_RESOURCES(TRUE);

		for (int i = 0; i < objects_size; i++) {
			SetEvent(hObjects[i]);
			DWORD ret = wait_for_multiple_objects_enhanced(i + 1, hObjects, 10000, FALSE);
			ASSERT_INT_EQ(ret, i + WAIT_OBJECT_0_ENHANCED);
			ResetEvent(hObjects[i]);
		}

		//TEST_RESOURCES(FALSE);
		TEST_DONE();
	}

	{
		TEST_START("Signal: Wait-any with latent events (WAIT_TIMEOUT_ENHANCED)");
		//TEST_RESOURCES(TRUE);

		for (int i = 0; i < objects_size; i++) ResetEvent(hObjects[i]);
		DWORD ret = wait_for_multiple_objects_enhanced(objects_size, hObjects, 250, FALSE);
		ASSERT_INT_EQ(ret, WAIT_TIMEOUT_ENHANCED);

		//TEST_RESOURCES(FALSE);
		TEST_DONE();
	}

	{
		TEST_START("Signal: Wait-any with async event in positions 1-300 (WAIT_OBJECT_0_ENHANCED offset)");
		//TEST_RESOURCES(TRUE);

		for (int i = 0; i < objects_size; i++) ResetEvent(hObjects[i]);
		for (int i = 0; i < objects_size; i++) {
			CloseHandle(CreateThread(NULL, 0, signal_test_set_event, hObjects[i], 0, NULL));
			DWORD ret = wait_for_multiple_objects_enhanced(objects_size, hObjects, 10000, FALSE);
			ASSERT_INT_EQ(ret, i + WAIT_OBJECT_0_ENHANCED);
			ResetEvent(hObjects[i]);
		}

		//TEST_RESOURCES(FALSE);
		TEST_DONE();
	}

	{
		TEST_START("Signal: Wait-any with abandoned mutex in positions 1-300 (WAIT_ABANDONED_0_ENHANCED offset)");
		//TEST_RESOURCES(TRUE);

		for (int i = 0; i < objects_size; i++) ResetEvent(hObjects[i]);
		for (int i = 0; i < objects_size; i++) {
			HANDLE original_event = hObjects[i];
			hObjects[i] = abandoned_mutux;
			DWORD ret = wait_for_multiple_objects_enhanced(objects_size, hObjects, 10000, FALSE);
			ASSERT_INT_EQ(ret, i + WAIT_ABANDONED_0_ENHANCED);
			hObjects[i] = original_event;
		}

		//TEST_RESOURCES(FALSE);
		TEST_DONE();
	}

	for (int i = 0; i < objects_size; i++) CloseHandle(hObjects[i]);
	CloseHandle(current_thread);
}

void
signal_tests()
{
	signal_test_wait_for_multiple_objects();
}
