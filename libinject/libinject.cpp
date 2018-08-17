#include <Windows.h>
#include <tlhelp32.h>

#include "libinject.h"

#define POST_COUNT 10

DWORD GetThreadID(DWORD pid)
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{
					if (te.th32OwnerProcessID == pid)
						return te.th32ThreadID;
				}
			} while (Thread32Next(h, &te));
		}
	}

	CloseHandle(h);
	return NULL;
}

// the dll to inject must export UnhookProc in order to call UnhookWindowsHookEx
bool InjectSignedDLL(DWORD pid, const char* dllPath) 
{
	DWORD threadID = GetThreadID(pid);
	HMODULE hLib = LoadLibraryA(dllPath);
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
	for (int i = 0; i < POST_COUNT; i++)
	{
		PostThreadMessageA(threadID, 0x1000, 0, (LPARAM)hook);
		Sleep(100);
	}

	FreeLibrary(hLib);
	return true;
}