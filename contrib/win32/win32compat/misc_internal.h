#pragma once
#include <VersionHelpers.h>

#define SSH_REGISTRY_ROOT L"SOFTWARE\\OpenSSH"
#define GOTO_CLEANUP_IF(_cond_,_err_) do {  \
    if ((_cond_)) {                         \
        hr = _err_;                         \
        goto cleanup;                       \
    }                                       \
} while(0)

#define NULL_DEVICE "/dev/null"
#define NULL_DEVICE_WIN "NUL"

#define IsWin7OrLess() (!IsWindows8OrGreater())

#define IS_INVALID_HANDLE(h) ( ((NULL == h) || (INVALID_HANDLE_VALUE == h)) ? 1 : 0 )
#define IS_VALID_HANDLE(h) (!IS_INVALID_HANDLE(h))
#define PROGRAM_DATA "__PROGRAMDATA__"
#define PROGRAM_DATAW L"__PROGRAMDATA__"
#define CYGWIN_PATH_PREFIX "/cygdrive/"

#define errno_from_Win32LastError() errno_from_Win32Error(GetLastError())

/* maximum potential size for paths when long paths are enabled */
#define PATH_MAX 32768

/* maximum size for user principal name as defined in ad schema */
#define MAX_UPN_LEN 1024

/* PTY windows size event type (for conhost and ssh-shellhost) */
#define PTY_SIGNAL_RESIZE_WINDOW  8u

/* maximum command line length */
#define MAX_CMD_LEN 8191

/* prog paths */
extern char* __progname;
extern char* __progdir;
extern wchar_t* __wprogdir;

/* %programdata% value */
extern char* __progdata;
extern wchar_t* __wprogdata;

static char *machine_domain_name;

extern char* chroot_path;
extern int chroot_path_len;
extern wchar_t* chroot_pathw;

/* removes first '/' for Windows paths that are unix styled. Ex: /c:/ab.cd */
wchar_t * resolved_path_utf16(const char *);
char* resolved_path_utf8(const char *);
void w32posix_initialize();
void w32posix_done();
void init_prog_paths();
void convertToBackslash(char *str);
void convertToBackslashW(wchar_t *str);
void convertToForwardslash(char *str);
int errno_from_Win32Error(int);
void unix_time_to_file_time(ULONG, LPFILETIME);
void file_time_to_unix_time(const LPFILETIME, time_t *);
int file_attr_to_st_mode(wchar_t * path, DWORD attributes);
void invalid_parameter_handler(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t);
void to_lower_case(char *s);
void to_wlower_case(wchar_t *s);
HANDLE get_user_token(const char* user, int impersonation);
int load_user_profile(HANDLE user_token, char* user);
int create_directory_withsddl(wchar_t *path, wchar_t *sddl);
int is_absolute_path(const char *);
int file_in_chroot_jail(HANDLE);
PSID lookup_sid(const wchar_t* name_utf16, PSID psid, DWORD * psid_len);
PSID get_sid(const char*);
int am_system();
int is_conpty_supported();
int exec_command_with_pty(int * pid, char* cmd, int in, int out, int err, unsigned int col, unsigned int row, int ttyfd);
char * build_exec_command(const char * command);
char * build_commandline_string(const char* cmd, char *const argv[], BOOLEAN prepend_module_path);
char* get_custom_lsa_package();
wchar_t* get_final_path_by_handle(HANDLE h);
int lookup_principal_name(const wchar_t * sam_account_name, wchar_t * user_principal_name);
BOOL is_bash_test_env();
int bash_to_win_path(const char *in, char *out, const size_t out_len);
void debug_assert_internal();