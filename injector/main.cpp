#include <Windows.h>
#include <tlhelp32.h>
#include <map>
#include <string>

#include "libinject.h"

std::map<std::string, std::vector<DWORD>> GetProcessList()
{
	std::map<std::string, std::vector<DWORD>> processList;
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == 0)
		return processList;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnapshot, &pe32))
	{
		CloseHandle(hSnapshot);
		return processList;
	}

	do
	{
		processList[pe32.szExeFile].push_back(pe32.th32ProcessID);
	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);
	return processList;
}

int main(int argc, char *argv[])
{
	if (argc > 2)
	{
		std::string proc = argv[1];
		std::string dll_path = argv[2];
		std::vector<DWORD> pids = GetProcessList()[proc];
		int injectIndex = -1;

		if (!pids.empty()) {
			printf("Select pid to inject into:\n"); 
			for (int i = 0; i < pids.size(); i++) {
				printf("[%d]: %d\n", i, pids[i]);
			}

			scanf("%d", &injectIndex);
			if (injectIndex != -1 && injectIndex < pids.size()) {
				bool success = InjectSetWindowsHookEx(pids[injectIndex], dll_path);
				//bool success = InjectManualMap(pids[injectIndex], "dummydll.dll", InjectionType::THREAD_HIJACK);
				printf("Inject status: %s\n", success ? "true" : "false");
			}
			else {
				printf("Invalid index specified: %d\n", injectIndex);
			}
		}
		else {
			printf("Unable to find pids for process: %s\n", proc.c_str());
		}
	}
	else {
		printf("Usage: injector.exe PID PATH_TO_DLL\n");
	}
}