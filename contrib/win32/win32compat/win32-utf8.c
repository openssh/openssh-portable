/* 
 * Windows versions of functions implemented in utf8.c
 */
#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>

#include "console.h"


int
vfmprintf(FILE *stream, const char *fmt, va_list ap)
{
	DWORD saved_mode = 0, new_mode = 0;
	int ret;
	HANDLE hFile;
	hFile = get_console_handle(stream, &saved_mode);
	if(hFile != INVALID_HANDLE_VALUE &&
		((saved_mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
			new_mode = saved_mode & (~ENABLE_VIRTUAL_TERMINAL_PROCESSING);
			SetConsoleMode(hFile, new_mode);
	}
	
	ret = vfprintf(stream, fmt, ap);
	if (saved_mode != 0 && new_mode != saved_mode)
		SetConsoleMode(hFile, saved_mode);
	return ret;
}

int
mprintf(const char *fmt, ...)
{
	int ret = 0;
	va_list ap;
	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	return ret;
}

int
fmprintf(FILE *stream, const char *fmt, ...)
{
	int ret = 0;
	va_list ap;
	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	return ret;
}

int
snmprintf(char *buf, size_t len, int *written, const char *fmt, ...)
{
	int ret;
	va_list valist;
	va_start(valist, fmt);
	ret = vsnprintf_s(buf, len, _TRUNCATE, fmt, valist);		
	va_end(valist);
	if (written != NULL && ret != -1)
		*written = ret;
	return ret;
}

/* TODO - Make windows implementation insync with Unix */
int
vasnmprintf(char **str, size_t maxsz, int *wp, const char *fmt, va_list ap)
{
	int ret;
	size_t sz;

	if((sz = vsnprintf(NULL, 0, fmt, ap)) < 0)
		return -1;

	*str = (char *) malloc(sizeof(char) * (sz + 1));
	ret = vsnprintf_s(*str, sz + 1, _TRUNCATE, fmt, ap);		
	if (wp != NULL && ret != -1)
		*wp = ret;

	return ret;
}

int
asmprintf(char **outp, size_t sz, int *written, const char *fmt, ...)
{
	int ret;
	va_list valist;
	va_start(valist, fmt);
	ret = vasnmprintf(outp, sz, written, fmt, valist);
	va_end(valist);

	return ret;
}

void
msetlocale(void)
{
	// allow console output of unicode characters
	SetConsoleOutputCP(CP_UTF8);
}

