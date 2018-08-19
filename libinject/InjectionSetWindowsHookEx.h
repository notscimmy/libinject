#pragma once

#include "InjectionBase.h"

#define DEFAULT_NOTIFY_COUNT 20

class InjectionSetWindowsHookEx : public InjectionBase
{
private:
	std::string dllPath;
	int notifyCount;

public:
	InjectionSetWindowsHookEx(DWORD pid, std::string dllPath);
	InjectionSetWindowsHookEx(DWORD pid, std::string dllPath, int notifyCount);

	bool Inject();
};