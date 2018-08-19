#pragma once

#include <Windows.h>
#include <string>
#include <vector>

enum class InjectionType
{
	CREATE_REMOTE_THREAD,
	THREAD_HIJACK
};

/*
	Injects the dll at dllPath using SetWindowsHookEx. This injection method
	requires a function "UnhookProc" to be exported in your dll. Please see
	the dummydll example for more information. Keep in mind that this method
	will only work on UI applications.

	@param pid the target process id to inject into
	@param dllPath the location of the dll to inject
	@param notifyCount optional argument for how many times UnhookProc should
					   be signalled to be called
	@return true if injection was successful, false if failed
*/
bool InjectSetWindowsHookEx(DWORD pid, std::string dllPath, int notifyCount = 0);

/*
	Injects the dll at dllPath by using the double pulsar shellcode. This does
	not require "UnhookProc" to be exported. Thankfully the shellcode also sets
	up SEH (structured exception handling) for us. For reference, dummydll has
	SEH enabled.

	@param pid the target process id to inject into
	@param dllPath the location of the dll to inject
	@param type the method to execute the injected shellcode (see InjectionType)
	@return true if injetion was successful, false if failed
*/
bool InjectManualMap(DWORD pid, std::string dllPath, InjectionType type);

/*
	Injects the dll defined as a byte buffer by using the double pulsar shellcode. 
	This does not require "UnhookProc" to be exported. Thankfully the shellcode also 
	sets up SEH (structured exception handling) for us. For reference, dummydll has
	SEH enabled.

	@param pid the target process id to inject into
	@param buffer the vector of bytes that represents an equivalent dll on disk
	@param type the method to execute the injected shellcode (see InjectionType)
	@return true if injetion was successful, false if failed
*/
bool InjectManualMap(DWORD pid, std::vector<unsigned char> buffer, InjectionType type);
