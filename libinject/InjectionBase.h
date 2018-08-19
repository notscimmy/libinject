#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <fstream>
#include <iterator>

class InjectionBase
{
protected:
	DWORD targetPID;

	DWORD GetThreadID();
	std::vector<unsigned char> GetBytesFromFile(std::string filePath);

public:
	InjectionBase(DWORD pid);
	virtual bool Inject() = 0;
};