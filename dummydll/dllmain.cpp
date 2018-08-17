#include <Windows.h>

void WorkerThread()
{
	while (true)
	{
		MessageBoxA(NULL, "Test MessageBox", "DummyDLL", NULL);
		Sleep(1000);
	}
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpBlah)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		wchar_t name[4096];

		GetModuleFileNameW(hinstDLL, name, 4096);
		LoadLibrary(name);

		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkerThread, 0, 0, 0);
	}

	return TRUE;
}

static bool isHooked = true;

// https://msdn.microsoft.com/en-us/library/ms644981(v=VS.85).aspx
// we hook this callback when using SetWindowsHookEx on WH_GETMESSAGE
// hence the lParam is a pointer to a MSG struct
extern "C" __declspec(dllexport) LRESULT CALLBACK UnhookProc(int code, WPARAM wParam, LPARAM lParam)
{
	MSG *msg = (MSG*)lParam;

	if (isHooked && msg->message == 0x1000)
	{
		UnhookWindowsHookEx((HHOOK)msg->lParam);
		isHooked = false;
		MessageBoxA(NULL, "Called UnhookWindowsHookEx", "DummyDLL", NULL);
	}

	return CallNextHookEx(0, code, wParam, lParam);
}