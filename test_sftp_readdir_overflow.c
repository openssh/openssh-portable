/*
 * Test for path truncation vulnerability in sftp-server.c process_readdir()
 * 
 * Bug: When constructing pathname in snprintf(), if path + "/" + d_name > PATH_MAX,
 * the pathname is silently truncated. lstat() then operates on the wrong file.
 * 
 * Compile: gcc -o test_sftp_readdir_overflow test_sftp_readdir_overflow.c
 * Run: ./test_sftp_readdir_overflow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

/* Simulate the vulnerable code from sftp-server.c process_readdir() */
void test_path_truncation_vulnerability(void)
{
	char long_path[PATH_MAX - 10];  /* Near PATH_MAX */
	char pathname[PATH_MAX];
	char filename[300];
	const char *dirent_d_name = "testfile.txt";
	
	/* Create a very long path name that will exceed PATH_MAX when combined with filename */
	memset(long_path, 'a', sizeof(long_path) - 1);
	long_path[sizeof(long_path) - 1] = '\0';
	
	printf("[*] Testing path truncation vulnerability in snprintf()\n");
	printf("[*] long_path length: %zu\n", strlen(long_path));
	printf("[*] PATH_MAX: %d\n", PATH_MAX);
	printf("[*] d_name: %s (length: %zu)\n", dirent_d_name, strlen(dirent_d_name));
	
	/* This is the vulnerable code from sftp-server.c:1149-1151 */
	/* XXX OVERFLOW ? */
	snprintf(pathname, sizeof pathname, "%s%s%s", long_path,
	    strcmp(long_path, "/") ? "/" : "", dirent_d_name);
	
	printf("[*] Result pathname length: %zu (should be %zu)\n", 
	       strlen(pathname), 
	       strlen(long_path) + 1 + strlen(dirent_d_name));
	
	/* The bug: pathname was truncated */
	if (strlen(pathname) < strlen(long_path) + 1 + strlen(dirent_d_name)) {
		printf("\n[BUG DETECTED] Path truncation occurred!\n");
		printf("[!] Expected length: %zu\n", strlen(long_path) + 1 + strlen(dirent_d_name));
		printf("[!] Actual length:   %zu\n", strlen(pathname));
		printf("[!] Lost %zu bytes\n", 
		       strlen(long_path) + 1 + strlen(dirent_d_name) - strlen(pathname));
		
		/* Show the truncated path - it no longer ends with the filename */
		printf("[!] Last 50 chars of pathname: ...%s\n", 
		       pathname + (strlen(pathname) > 50 ? strlen(pathname) - 50 : 0));
		printf("[!] Does NOT contain filename '%s' properly\n", dirent_d_name);
		printf("\n[IMPACT] lstat() will operate on wrong file due to truncation\n");
		return;  /* Bug confirmed */
	}
	
	printf("[OK] No truncation occurred (unexpected)\n");
}

/* Demonstrate the fix: check buffer size before snprintf */
void test_fixed_version(void)
{
	char long_path[PATH_MAX - 10];
	char pathname[PATH_MAX];
	char filename[300];
	const char *dirent_d_name = "testfile.txt";
	size_t path_len;
	
	memset(long_path, 'a', sizeof(long_path) - 1);
	long_path[sizeof(long_path) - 1] = '\0';
	
	printf("\n\n[TESTING FIXED VERSION]\n");
	printf("============================================\n");
	
	/* Fixed code: check for overflow before snprintf */
	path_len = strlen(long_path);
	
	/* Calculate required space: path + "/" + d_name + null terminator */
	size_t required_len = path_len + 1 + strlen(dirent_d_name) + 1;
	
	if (required_len > sizeof(pathname)) {
		printf("[FIX] Detected path overflow! Required %zu bytes, have %zu\n", 
		       required_len, sizeof(pathname));
		printf("[FIX] Would reject this operation or allocate larger buffer\n");
		return;  /* Properly handled */
	}
	
	/* Safe to proceed */
	snprintf(pathname, sizeof pathname, "%s%s%s", long_path,
	    strcmp(long_path, "/") ? "/" : "", dirent_d_name);
	
	printf("[FIX] Path constructed safely, length: %zu\n", strlen(pathname));
}

int main(void)
{
	printf("========================================\n");
	printf("OpenSSH SFTP Path Truncation Vulnerability Test\n");
	printf("Bug Location: sftp-server.c:1149-1156 (process_readdir)\n");
	printf("========================================\n\n");
	
	test_path_truncation_vulnerability();
	test_fixed_version();
	
	printf("\n========================================\n");
	printf("Test Summary:\n");
	printf("- Vulnerability: Silent path truncation in snprintf()\n");
	printf("- Impact: Information disclosure, wrong files stat'd\n");
	printf("- Fix: Add bounds checking before snprintf()\n");
	printf("========================================\n");
	
	return 0;
}
