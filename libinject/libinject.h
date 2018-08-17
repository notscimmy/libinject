#pragma once

#include <Windows.h>

bool InjectSignedDLL(DWORD pid, const char* dllPath);