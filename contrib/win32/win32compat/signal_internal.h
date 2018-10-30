#include <Windows.h>
#include <process.h>
#include "misc_internal.h"

/* child processes */
#define MAX_CHILDREN 512

struct _children {
	/* 
	 * array of handles and process_ids. 
	 * initial (num_children - num_zombies) are alive 
	 * rest are zombies 
	 */
	HANDLE handles[MAX_CHILDREN];
	DWORD process_id[MAX_CHILDREN];
	/* total children */
	DWORD num_children;
	/* #zombies */
	/* (num_children - zombies) are live children */
	DWORD num_zombies;
};


int sw_initialize();
int register_child(HANDLE child, DWORD pid);
int sw_remove_child_at_index(DWORD index);
int sw_child_to_zombie(DWORD index);
void sw_cleanup_child_zombies();

struct _timer_info {
	HANDLE timer;
	ULONGLONG ticks_at_start; /* 0 if timer is not live */
	__int64 run_time_sec; /* time in seconds, timer is set to go off from ticks_at_start */
};
int sw_init_timer();

#define MAXIMUM_WAIT_OBJECTS_ENHANCED 1024
#define WAIT_OBJECT_0_ENHANCED 0x00000000
#define WAIT_ABANDONED_0_ENHANCED 0x10000000
#define WAIT_TIMEOUT_ENHANCED 0x20000000
#define WAIT_IO_COMPLETION_ENHANCED 0x30000000
#define WAIT_FAILED_ENHANCED WAIT_FAILED

DWORD wait_for_multiple_objects_enhanced(_In_ DWORD  nCount, _In_ const HANDLE *lpHandles,
	_In_ DWORD dwMilliseconds, _In_ BOOL bAlertable);