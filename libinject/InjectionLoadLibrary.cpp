#include "InjectionLoadLibrary.h"

InjectionLoadLibrary::InjectionLoadLibrary(DWORD pid, std::string dllPath) : InjectionBase(pid), dllPath(dllPath) {}

bool InjectionLoadLibrary::Inject()
{
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
	if (!proc)
		return false;

	LPVOID pDll = VirtualAllocEx(proc, 0, dllPath.length(), MEM_COMMIT, PAGE_READWRITE);
	if (!pDll) 
		return false;

	BOOL wpmSuccess = WriteProcessMemory(proc, pDll, (LPVOID)dllPath.c_str(), dllPath.length(), NULL);
	if (!wpmSuccess)
		return false;

	LPVOID pLoadLibrary = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (!pLoadLibrary)
		return false;

	HANDLE hLoadLibraryThread = CreateRemoteThread(proc, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibrary, pDll, NULL, NULL);
	if (!hLoadLibraryThread)
		return false;

	WaitForSingleObject(hLoadLibraryThread, INFINITE);

	VirtualFreeEx(proc, pDll, dllPath.length(), MEM_RELEASE);
	return true;
}