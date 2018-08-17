#include <Windows.h>
#include <tlhelp32.h>
#include <map>
#include <string>

#include "libinject.h"

std::map<std::string, DWORD> GetProcessList()
{
	std::map<std::string, DWORD> processList;
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
		processList[pe32.szExeFile] = pe32.th32ProcessID;
	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);
	return processList;
}

int main(int argc, char *argv[])
{
	if (argc > 1)
	{
		std::string proc = argv[1];
		DWORD pid = GetProcessList()[proc];

		if (pid != 0)
		{
			bool success = InjectSignedDLL(pid, "dummydll.dll");
			printf("Inject status: %s\n", success ? "true" : "false");
		}
		else
			printf("Unable to find pid for process: %s\n", proc.c_str());
	}
	else
		printf("Provide a process to inject as the first argument to this program\n");
}