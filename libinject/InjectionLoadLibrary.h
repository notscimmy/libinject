#pragma once

#include "InjectionBase.h"

class InjectionLoadLibrary : public InjectionBase
{
private:
	std::string dllPath;

public:
	InjectionLoadLibrary(DWORD pid, std::string dllPath);

	bool Inject();
};