#pragma once

#include "InjectionBase.h"
#include "DoublePulsarPayload.h"

class InjectionManualMap : public InjectionBase
{
private:
	std::string dllPath;
	std::vector<unsigned char> buffer;
	bool useCRT;

	std::vector<unsigned char> ConstructPayload(std::vector<unsigned char> dllBytes);

	bool InjectHelper(std::vector<unsigned char> payload);
	bool InjectWithFile();
	bool InjectWithBuffer();

public:
	InjectionManualMap(DWORD pid, std::string dllPath, bool useCRT);
	InjectionManualMap(DWORD pid, std::vector<unsigned char> buffer, bool useCRT);

	bool Inject();
};