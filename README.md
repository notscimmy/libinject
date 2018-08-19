# libinject - Inject 64-bit DLLs into arbitrary processes

## Features
* **SetWindowsHookEx**
  * Does not require a handle for injection, but requires the target process to be a UI application due to the necessity of a message loop.
  * Requires the DLL to be injected to export `UnhookProc`. The injector program notifies the DLL with message ID `0x1000` via `PostThreadMessage` in order to unhook the hook set on `WH_MESSAGE`. Take a look at the `dummydll` project for more information on how to create a DLL to be used with this injection method.
  * This is basically equivalent to a `LoadLibrary` injector, it is unlikely to work well with most anti-cheats. You could try signing your DLL and hope for the best though.
  * This method is also how OBS and Discord inject their DLLs. Since anti-cheats that run in the kernel often implement `ObRegisterCallbacks` for handle stripping as well as `iterate over the handle table in the kernel` to prevent any handle elevation tricks, legitimate programs must use similar "handleless" injection methods.
* **Doublepulsar manual mapper**
  * Utilizes the shellcode outlined in this article: <https://www.countercept.com/our-thinking/doublepulsar-usermode-analysis-generic-reflective-dll-loader/>
  * The shellcode cannot be used out of the box due to these steps:
    1. Calls DllMain entrypoint
    2. Calls user-defined function via ordinal
    3. Zeroes out memory allocated for the DLL
    4. Frees that memory
    5. ```RtlDeleteFunctionTable``` to remove SEH handling
    6. Zeroes out (most) memory allocated for the bootstrap loader
  * Shellcode in this project has been modified to **NOT** free the DLL nor remove SEH handling
  * libinject supports two methods of executing the shellcode: **CreateRemoteThread** and **Thread Hijacking**
  
## Usage

`libinject` is compiled to a static library that you can include into your project. <br>
Simply include the header, and call any of the functions that match your injection needs. <br>
The `injector` project also includes a more detailed usage of this library. <br>

```cpp 
bool InjectSetWindowsHookEx(DWORD pid, std::string dllPath, int notifyCount = 0);

bool InjectManualMap(DWORD pid, std::string dllPath, InjectionType type);

bool InjectManualMap(DWORD pid, std::vector<unsigned char> buffer, InjectionType type);
```
