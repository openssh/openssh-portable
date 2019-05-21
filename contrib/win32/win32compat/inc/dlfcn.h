#pragma once
#include <Windows.h>
#define RTLD_NOW 0

HMODULE dlopen(const char *filename, int flags);

int dlclose(HMODULE handle);

FARPROC dlsym(HMODULE handle, const char *symbol);

char * dlerror();
