#include "InjectionSetWindowsHookEx.h"

InjectionSetWindowsHookEx::InjectionSetWindowsHookEx(DWORD pid, std::string dllPath) : 
	InjectionBase(pid), dllPath(dllPath), notifyCount(DEFAULT_NOTIFY_COUNT) {}

InjectionSetWindowsHookEx::InjectionSetWindowsHookEx(DWORD pid, std::string dllPath, int notifyCount) :
	InjectionBase(pid), dllPath(dllPath), notifyCount(notifyCount) {}

bool InjectionSetWindowsHookEx::Inject()
{
	DWORD threadID = GetThreadID();
	HMODULE hLib = LoadLibraryA(dllPath.c_str());
	if (!hLib)
		return false;

	LPVOID unhookProc = GetProcAddress(hLib, "UnhookProc");
	if (!unhookProc)
	{
		FreeLibrary(hLib);
		return false;
	}

	// force our library to be loaded whenever the message loop turns by hooking WH_GETMESSAGE
	HHOOK hook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)unhookProc, hLib, threadID);
	if (!hook)
	{
		FreeLibrary(hLib);
		return false;
	}

	// post a message with our defined id (0x1000) which will unhook what we did above
	// at that point the dll will have been loaded into our target process
	for (int i = 0; i < notifyCount; i++)
	{
		PostThreadMessageA(threadID, 0x1000, 0, (LPARAM)hook);
		Sleep(100);
	}

	FreeLibrary(hLib);
	return true;
}