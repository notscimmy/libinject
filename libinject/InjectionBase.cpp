#include "InjectionBase.h"

InjectionBase::InjectionBase(DWORD pid) : targetPID(pid) {}

DWORD InjectionBase::GetThreadID()
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
					if (te.th32OwnerProcessID == targetPID)
					{
						CloseHandle(h);
						return te.th32ThreadID;
					}
				}
			} while (Thread32Next(h, &te));
		}
	}

	
	return NULL;
}

std::vector<unsigned char> InjectionBase::GetBytesFromFile(std::string filePath)
{
	std::ifstream file(filePath, std::ios::binary);

	file.unsetf(std::ios::skipws);

	std::streampos fileSize;

	file.seekg(0, std::ios::end);
	fileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<unsigned char> vec;
	vec.reserve(fileSize);

	vec.insert(vec.begin(),
		std::istream_iterator<unsigned char>(file),
		std::istream_iterator<unsigned char>());

	return vec;
}