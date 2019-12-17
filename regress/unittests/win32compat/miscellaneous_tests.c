#include "includes.h"
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <misc_internal.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "../test_helper/test_helper.h"
#include "tests.h"

int retValue;

// The ioctl() testcase is failing when ran from Run-OpenSSHUnitTest.
void 
test_ioctl()
{
	if(!isatty(fileno(stdin))) return;

	TEST_START("ioctl");

	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	retValue = ioctl(fileno(stdin), TIOCGWINSZ, &ws);
	ASSERT_INT_EQ(retValue, 0);
	ASSERT_INT_NE(ws.ws_col, 0);
	ASSERT_INT_NE(ws.ws_row, 0);
	ASSERT_INT_NE(ws.ws_xpixel, 0);
	ASSERT_INT_NE(ws.ws_ypixel, 0);	

	TEST_DONE();
}

void
test_path_conversion_utilities()
{
	TEST_START("path conversion utilities");

	char *s = "c:\\testdir\\test";
	char *windows_style_path = dup_str(s);
	int len = strlen(windows_style_path);
	char *backup = malloc(len + 1);
	strncpy(backup, windows_style_path, len);
	backup[len] = '\0';

	convertToForwardslash(windows_style_path);

	char *tmpStr = strstr(windows_style_path, "\\");
	ASSERT_PTR_EQ(tmpStr, NULL);

	convertToBackslash(windows_style_path);
	tmpStr = strstr(windows_style_path, "/");
	ASSERT_PTR_EQ(tmpStr, NULL);

	retValue = strcmp(windows_style_path, backup);
	ASSERT_INT_EQ(retValue, 0);

	free(windows_style_path);

	TEST_DONE();
}

void
test_sanitizedpath()
{
	TEST_START("win32 program dir");
	
	char *win32prgdir_utf8 = __progdir;
	ASSERT_PTR_NE(win32prgdir_utf8, NULL);

	ASSERT_PTR_EQ(resolved_path_utf16(NULL), NULL);
	ASSERT_INT_EQ(errno, EINVAL);

	wchar_t *win32prgdir = utf8_to_utf16(win32prgdir_utf8);
	wchar_t *ret = resolved_path_utf16(win32prgdir_utf8);
	/* resolved path will return in unix file format ex - c:/test/1/ */
	convertToBackslashW(ret);
	retValue = wcscmp(win32prgdir, ret);
	ASSERT_INT_EQ(retValue, 0);
	free(ret);

	char win32prgdir_len = strlen(win32prgdir_utf8);
	char *tmp_path = malloc(win32prgdir_len + 2); /* 1-NULL and 1-adding "/" */
	tmp_path[0] = '/';
	strcpy(tmp_path+1, win32prgdir_utf8);
	tmp_path[win32prgdir_len+1] = '\0';

	ret = resolved_path_utf16(tmp_path);
	/* resolved path will return in unix file format ex - c:/test/1/ */
	convertToBackslashW(ret);
	retValue = wcscmp(win32prgdir, ret);
	ASSERT_INT_EQ(retValue, 0);
	free(ret);

	char s1[4];
	wchar_t s2[4];
	s1[0] = '/', s1[1] = win32prgdir[0],  s1[2] = ':', s1[3] = '\0';
	s2[0] = win32prgdir[0], s2[1] = ':', s2[2] = '\\', s2[3] = '\0';	
	ret = resolved_path_utf16(s1);
	/* resolved path will return in unix file format ex - c:/test/1/ */
	convertToBackslashW(ret);
	retValue = wcscmp(ret, s2);
	ASSERT_INT_EQ(retValue, 0);
	free(ret);

	free(win32prgdir);

	TEST_DONE();
}

void
test_pw()
{
	TEST_START("pw tests");

	struct passwd *pw = NULL;
	pw = getpwuid(0);
	ASSERT_PTR_NE(pw, NULL);

	struct passwd *pw1 = NULL;
	char *user = dup_str(pw->pw_name);
	pw1 = getpwnam(user);
	ASSERT_PTR_NE(pw1, NULL);

	TEST_DONE();
}

void
test_statvfs()
{
	TEST_START("test statvfs");

	struct statvfs st;
	char cwd[PATH_MAX];

	char *tmp = getcwd(cwd, PATH_MAX);
	ASSERT_PTR_NE(tmp, NULL);

	retValue = statvfs(NULL, &st);
	ASSERT_INT_EQ(retValue, -1);

	explicit_bzero(&st, sizeof(st));
	retValue = statvfs(cwd, &st);
	ASSERT_INT_EQ(retValue, 0);
	ASSERT_INT_NE(st.f_bavail, 0);

	TEST_DONE();
}

void test_realpath()
{
	TEST_START("test realpath");

	char resolved_path[PATH_MAX];
	char *ret = NULL;
	char *expectedOutput1 = "/c:/windows/system32";
	char *expectedOutput2 = "/c:/";

	ret = realpath(NULL, NULL);
	ASSERT_PTR_EQ(ret, NULL);

	ret = realpath("c:\\windows\\system32", NULL);
	ASSERT_PTR_EQ(ret, NULL);

	ret = realpath(NULL, resolved_path);
	ASSERT_PTR_EQ(ret, NULL);

	ret = realpath("c:\\windows\\system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("/c:\\windows\\system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("/c:\\windows\\.\\system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("/c:\\windows\\.\\..\\windows\\system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("/c:\\windows/.\\..\\windows\\system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("c:/windows/system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("/c:/windows/system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("c:", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput2);

	ret = realpath("c:\\", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput2);

	ret = realpath("/c:", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput2);

	ASSERT_PTR_NE(ret = realpath("/c:/..", resolved_path), NULL);
	ASSERT_STRING_EQ(ret, "/");

	ASSERT_PTR_NE(ret = realpath("/", resolved_path), NULL);
	ASSERT_STRING_EQ(ret, "/");

	ASSERT_PTR_NE(ret = realpath("\\", resolved_path), NULL);
	ASSERT_STRING_EQ(ret, "/");


	TEST_DONE();
}

void
test_chroot()
{
	int fd;
	FILE *f;
	char path[PATH_MAX], test_root[PATH_MAX];

	/* test directory setup */
	_wsystem(L"RD /S /Q chroot-testdir >NUL 2>&1");
	CreateDirectoryW(L"chroot-testdir", NULL);
	CreateDirectoryW(L"chroot-testdir\\world", NULL);
	_wsystem(L"echo in-world > chroot-testdir\\world\\w.Txt");
	CreateDirectoryW(L"chroot-testdir\\jail", NULL);
	CreateDirectoryW(L"chroot-testdir\\jail\\d1", NULL);
	_wsystem(L"echo in-jail > chroot-testdir\\jail\\d1\\j.Txt");
	/* create links to world within jail */
	_wsystem(L"mklink /D chroot-testdir\\jail\\world-sl ..\\world");
	_wsystem(L"mklink /J chroot-testdir\\jail\\world-jn chroot-testdir\\world");
		
	TEST_START("chroot on invalid path");
	ASSERT_INT_EQ(chroot("blah"), -1);
	ASSERT_INT_EQ(chroot("\\c:\\blah"), -1);
	ASSERT_INT_EQ(chroot("/c:/blah"), -1);
	TEST_DONE();

	TEST_START("access world before chroot");
	ASSERT_INT_NE(fd = open("chroot-testdir\\jail\\world-jn\\w.Txt", 0), -1);
	close(fd);
	ASSERT_PTR_NE(f = fopen("chroot-testdir\\jail\\world-jn\\w.Txt", "r"), NULL);
	fclose(f);
	TEST_DONE();

	TEST_START("real chroot now");
	getcwd(path, PATH_MAX);
	getcwd(test_root, PATH_MAX);
	strcat(path, "\\chroot-testdir\\jail");
	ASSERT_INT_EQ(chdir(path), 0);
	ASSERT_INT_EQ(chroot(path), 0);
	TEST_DONE();

	TEST_START("chdir; getcwd and realpath");
	ASSERT_PTR_NE(getcwd(path, PATH_MAX), NULL);
	ASSERT_STRING_EQ(path, "\\");
	ASSERT_INT_NE(chdir(test_root), 0);
	ASSERT_INT_EQ(chdir("d1"), 0);
	ASSERT_PTR_NE(realpath("..", path), NULL);
	ASSERT_STRING_EQ(path, "/");
	ASSERT_PTR_NE(getcwd(path, PATH_MAX), NULL);
	ASSERT_STRING_EQ(path, "\\d1");
	ASSERT_PTR_NE(realpath(".", path), NULL);
	ASSERT_STRING_EQ(path, "/d1");
	ASSERT_PTR_EQ(realpath("..\\..\\", path), NULL);
	ASSERT_INT_EQ(errno, EACCES);
	TEST_DONE();

	TEST_START("file io within jail");
	ASSERT_INT_NE(fd = open("\\d1\\j.txt", 0), -1);
	close(fd);
	ASSERT_INT_NE(fd = open("\\d1/j.txt", 0), -1);
	close(fd);
	ASSERT_INT_NE(fd = open("/d1/j.txt", 0), -1);
	close(fd);
	ASSERT_INT_NE(fd = open("/dev/null", 0), -1);
	close(fd);
	ASSERT_PTR_NE(f = fopen("\\d1\\j.txt", "r"), NULL);
	fclose(f);
	ASSERT_PTR_NE(f = fopen("/dev/null", "w"), NULL);
	fclose(f);
	ASSERT_INT_EQ(chdir("/"), 0);
	ASSERT_INT_NE(fd = open("d1/j.txt", 0), -1);
	close(fd);
	ASSERT_PTR_NE(f = fopen("d1\\j.txt", "r"), NULL);
	fclose(f);
	ASSERT_INT_EQ(chdir("\\d1"), 0);
	ASSERT_INT_NE(fd = open("j.txt", 0), -1);
	close(fd);
	ASSERT_PTR_NE(f = fopen("j.txt", "r"), NULL);
	fclose(f);
	TEST_DONE();

	TEST_START("access world after chroot");
	ASSERT_INT_EQ(chdir("/"), 0);
	ASSERT_INT_EQ(fd = open(test_root, 0), -1);
	ASSERT_INT_EQ(errno, ENOENT);
	ASSERT_INT_EQ(fd = open("..\\", 0), -1);
	ASSERT_INT_EQ(errno, EACCES);
	ASSERT_INT_EQ(fd = open("../", 0), -1);
	ASSERT_INT_EQ(errno, EACCES);
	ASSERT_INT_EQ(fd = open("../outofjail.txt", O_CREAT), -1);
	ASSERT_INT_EQ(errno, EACCES);
	/* ensure outofjail.txt is not created by the above call*/
	path[0] = '\0';
	strcat(path, test_root);
	strcat(path, "\\chroot-testdir\\outofjail.txt");
	ASSERT_INT_EQ(fd = _open(path, 0), -1);
	ASSERT_INT_EQ(errno, ENOENT);
	ASSERT_INT_EQ(fd = open("world-jn\\w.Txt", 0), -1);
	ASSERT_INT_EQ(errno, EACCES);
	ASSERT_PTR_EQ(f = fopen("world-jn\\w.Txt", "r"), NULL);
	ASSERT_INT_EQ(errno, EACCES); 
	ASSERT_INT_EQ(fd = open("world-sl\\w.Txt", 0), -1);
	ASSERT_INT_EQ(errno, EACCES); 
	ASSERT_PTR_EQ(f = fopen("world-sl\\w.Txt", "r"), NULL);
	ASSERT_INT_EQ(errno, EACCES); 
	TEST_DONE();


	//_wsystem(L"RD /S /Q chroot-testdir >NUL 2>&1");
}

void
test_build_exec_command()
{
	char *out;

	TEST_START("arg is null");
	out = build_exec_command(NULL);
	ASSERT_PTR_EQ(out, NULL);
	TEST_DONE();

	TEST_START("scp tests");
	out = build_exec_command("sCp -arg");	
	ASSERT_STRING_EQ(out, "scp.exe -arg");
	free(out);
	out = build_exec_command("sCp.exe -arg1 -arg2");
	ASSERT_STRING_EQ(out, "scp.exe -arg1 -arg2");
	free(out);
	TEST_DONE();

	TEST_START("sftp tests");
	out = build_exec_command("internal-sftp \"arg1 arg2\"");
	ASSERT_STRING_EQ(out, "sftp-server.exe \"arg1 arg2\"");
	free(out);
	out = build_exec_command("SFTP-server.exe -arg");
	ASSERT_STRING_EQ(out, "sftp-server.exe -arg");
	free(out);
	out = build_exec_command("sftp-SERVER -arg");	
	ASSERT_STRING_EQ(out, "sftp-server.exe -arg");
	free(out);
	TEST_DONE();
}

void
test_build_commandline_string()
{
	char *out, in[PATH_MAX], buf[PATH_MAX];

	TEST_START("cmd is null");
	out = build_commandline_string(NULL, NULL, TRUE);
	ASSERT_PTR_EQ(out, NULL);
	TEST_DONE();

	TEST_START("arg is null");
	out = build_commandline_string("\"c:\\windows\\system32\\cmd.exe\" /c arg", NULL, FALSE);
	ASSERT_STRING_EQ(out, "\"c:\\windows\\system32\\cmd.exe\" /c arg");
	free(out);
	out = build_commandline_string("cmd.exe /c ping.exe", NULL, FALSE);
	ASSERT_STRING_EQ(out, "\"cmd.exe\" /c ping.exe");
	sprintf_s(in, PATH_MAX, "\"%s\\%s\"", __progdir, "ssh-shellhost.exe\" -c \"arg1 arg2\"");
	out = build_commandline_string(in, NULL, TRUE);
	ASSERT_STRING_EQ(out, in);
	out = build_commandline_string("\"ssh-shellhost.exe\" -c \"arg1 arg2\"", NULL, TRUE);
	sprintf_s(buf, PATH_MAX, "\"%s\\%s", __progdir, "ssh-shellhost.exe\" -c \"arg1 arg2\"");
	ASSERT_STRING_EQ(out, buf);
	free(out);
	out = build_commandline_string("\"cmd.exe\" /c \"arg1 arg2\"", NULL, FALSE);
	ASSERT_STRING_EQ(out, "\"cmd.exe\" /c \"arg1 arg2\"");
	free(out);
	TEST_DONE();

	char *argv[4] = { NULL, };
	argv[0] = "\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"";
	argv[1] = "-c";
	argv[2] = "arg1 arg2";
	TEST_START("arg is not null");
	out = build_commandline_string(argv[0], argv + 1, TRUE);
	sprintf_s(buf, PATH_MAX, "%s %s %s", argv[0], argv[1], "\"arg1 arg2\"");
	ASSERT_STRING_EQ(out, buf);
	free(out);
	argv[0] = "C:\\my folder\\bash.exe";
	argv[2] = "\"arg1\\arg2\"";
	out = build_commandline_string(argv[0], argv + 1, TRUE);
	sprintf_s(buf, PATH_MAX, "\"%s\" %s %s", argv[0], argv[1], "\\\"arg1\\arg2\\\"");
	ASSERT_STRING_EQ(out, buf);
	free(out);
	argv[2] = "\"arg1 arg2\\\"";
	out = build_commandline_string(argv[0], argv + 1, TRUE);
	sprintf_s(buf, PATH_MAX, "\"%s\" %s %s", argv[0], argv[1], "\"\\\"arg1 arg2\\\\\\\"\"");
	ASSERT_STRING_EQ(out, buf);
	free(out);
	argv[0] = "\"c:\\cygwin64\\bin\\ba.exe\"";
	argv[2] = "arg1\\arg2";
	out = build_commandline_string(argv[0], argv + 1, TRUE);
	sprintf_s(buf, PATH_MAX, "%s %s %s", argv[0], argv[1], "arg1\\arg2");
	ASSERT_STRING_EQ(out, buf);
	free(out);
	argv[0] = "\"c:\\cygwin64\\bin\\ba.exe\"";
	argv[2] = "'arg1 \\arg2\\\"'";
	out = build_commandline_string(argv[0], argv + 1, TRUE);
	sprintf_s(buf, PATH_MAX, "%s %s %s", argv[0], argv[1], "'arg1 \\arg2\\\\\\\"'");
	ASSERT_STRING_EQ(out, buf);
	free(out);
	TEST_DONE();
}

void
miscellaneous_tests()
{
	//test_ioctl();
	test_path_conversion_utilities();
	test_sanitizedpath();
	test_pw();
	test_realpath();
	test_statvfs();
	test_chroot();
	test_build_exec_command();
	test_build_commandline_string();
}
