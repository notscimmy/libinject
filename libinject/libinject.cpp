#include <Windows.h>

#include "libinject.h"
#include "InjectionSetWindowsHookEx.h"
#include "InjectionManualMap.h"
#include "InjectionLoadLibrary.h"

bool InjectLoadLibrary(DWORD pid, std::string dllPath)
{
	InjectionLoadLibrary injector(pid, dllPath);
	return injector.Inject();
}

bool InjectSetWindowsHookEx(DWORD pid, std::string dllPath, int notifyCount)
{
	InjectionSetWindowsHookEx injector(pid, dllPath, notifyCount);
	return injector.Inject();
}

bool InjectManualMap(DWORD pid, std::string dllPath, InjectionType type)
{
	switch (type)
	{
		case InjectionType::CREATE_REMOTE_THREAD:
		{
			InjectionManualMap injector(pid, dllPath, true);
			return injector.Inject();
		}

		case InjectionType::THREAD_HIJACK:
		{
			InjectionManualMap injector(pid, dllPath, false);
			return injector.Inject();
		}

		default:
			return false;
	}
}

bool InjectManualMap(DWORD pid, std::vector<unsigned char> buffer, InjectionType type)
{
	switch (type)
	{
		case InjectionType::CREATE_REMOTE_THREAD:
		{
			InjectionManualMap injector(pid, buffer, true);
			return injector.Inject();
		}

		case InjectionType::THREAD_HIJACK:
		{
			InjectionManualMap injector(pid, buffer, false);
			return injector.Inject();
		}

		default:
			return false;
	}
}