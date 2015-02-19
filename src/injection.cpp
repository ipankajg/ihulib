/*++

Copyright (c) 2015, Pankaj Garg <pankaj@intellectualheaven.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

--*/

/*++

Module Name:

    injection.cpp

Module Description:

    Implements core functionality of injecting a DLL into another
    process. You can inject a DLL in a running process, by giving
    its PID or name. In case a name is given, the very first victim
    process is injected with the given DLL.

    It also provides functionality for launching a process and
    then injecting the DLL into that.

--*/

#if defined(_M_IX86)

#include <windows.h>
#include <stdio.h>
#include "ihulib.h"

//
// Application specific error codes
//
#define ERR_INJDLL_ERROR_BASE       0x20001000
#define ERR_PROCESS_NOT_FOUND       (ERR_INJDLL_ERROR_BASE + 1)
#define ERR_INVALID_PROCESS_ID      (ERR_INJDLL_ERROR_BASE + 2)

#define MAX_INC_EXC_SIZE            5120
#define MAX_FN_NAME_LENGTH          64

typedef struct _INJECTION_DATA
{
    // Required to inject DLL
    LPVOID mLoadLibraryW;
    LPVOID mGetProcAddr;
    LPVOID mFreeLibrary;
    LPVOID mGetModuleHandleW;
    LPVOID mDeleteFileW;
    LPVOID mSleep;

    // The dll and function name that injected code uses to load the DLL and
    // initialize it.
    WCHAR mDllName[MAX_PATH];
    CHAR mLoadFnName[MAX_FN_NAME_LENGTH];
    CHAR mUnloadFnName[MAX_FN_NAME_LENGTH];
    CHAR mGetRefFnName[MAX_FN_NAME_LENGTH];

    // Injector's DLL is passed the user supplied context.
    // Actual context data follows this structure in memory.
    ULONG mLoadContextSize;

} INJECTION_DATA, *PINJECTION_DATA;

// LoadLibraryW typedef
typedef HINSTANCE(WINAPI * PFNLOADLIBRARY) (LPCWSTR);

// FreeLibrary typedef
typedef HINSTANCE(WINAPI * PFNFREELIBRARY) (HMODULE);

// GetModuleHandle typedef
typedef HMODULE(WINAPI * PFNGETMODULEHANDLE) (LPCWSTR);

// GetProcAddress typedef
typedef FARPROC(WINAPI * PFNGETPROCADDRESS) (HMODULE, LPCSTR);

// DeleteFileW typedef
typedef BOOL(WINAPI * PFNDELETEFILE) (LPCWSTR);

// Sleep typedef
typedef void (WINAPI * PFNSLEEP) (DWORD);

// DLL's Initiate Patching function prototype
typedef void (WINAPI * PFNSERUMLOAD) (PVOID, ULONG);

// DLL's Deinit patching function typedef
typedef void (WINAPI * PFNSERUMUNLOAD) (void);

// DLL's thread usage count function typedef
typedef volatile LONG(WINAPI * PFNSERUMGETREFCOUNT) (void);

static VOID
ihiInitInjectionData(LPCWSTR inDllPath, PVOID inLoadContext,
                     ULONG inLoadContextSize, PINJECTION_DATA *outInjData,
                     PULONG outInjDataSize);

static void
ihiInjectedCode(LPVOID *inAddress);

static void
ihiInjectedCodeEnd();

static void
ihiUnloadCode(LPVOID * inAddress);

static void
ihiUnloadCodeEnd();

/*++

Routine Name:

    IhuGetProcessIdByName

Routine Description:

    This function should called to find the Process Id
    of a running process by supplying the process
    name.

Return:

    If the function is successful then processId of the process
    is returned and If the function fails then 0 is returned.

    In case of failure, call GetLastError for more information

--*/
DWORD WINAPI
IhuGetProcessIdByName(LPCWSTR inProcessName)
{
    DWORD processId = 0;
    DWORD errorCode = 0;

    IHU_PROCESS_LIST processList;
    IHU_PROCESS_LIST_ITER processListIter;
    IHU_PROCESS_INFO processInfo;

    if (IhuGetProcessList(processList) < 0)
    {
        errorCode = GetLastError();
        goto Exit;
    }

    bool processFound = false;

    for (processListIter = processList.begin();
         processListIter != processList.end(); ++processListIter)
    {
        processInfo = *processListIter;

        if (_wcsicmp(processInfo.mProcessName.c_str(), inProcessName) == 0)
        {
            processFound = true;
            break;
        }
    }

    if (processFound)
    {
        processId = processInfo.mProcessId;
    }
    else
    {
        errorCode = ERR_PROCESS_NOT_FOUND;
    }

Exit:

    SetLastError(errorCode);
    return processId;
}



/*++

Routine Name:

    IhuLaunchNewProcess

Routine Description:

    This function will create a new process and return
    process Id.

Return:

    If the function is successful then processId of the process
    is returned and If the function fails then 0 is returned.

    In case of failure, call GetLastError for more information

--*/
DWORD WINAPI
IhuLaunchNewProcess(LPCWSTR inExePath)
{
    STARTUPINFO startupInfo;
    PROCESS_INFORMATION procInfo;

    DWORD processId = 0;
    DWORD errorCode = 0;

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    ZeroMemory(&procInfo, sizeof(procInfo));

    wchar_t processCommandLine[MAX_PATH];
    wcscpy(processCommandLine, inExePath);

    BOOL bResult = CreateProcess(NULL,
                                 processCommandLine,
                                 NULL,
                                 NULL,
                                 FALSE,
                                 CREATE_SEPARATE_WOW_VDM |
                                 DEBUG_ONLY_THIS_PROCESS,
                                 NULL,
                                 NULL,
                                 &startupInfo,
                                 &procInfo);

    if (!bResult)
    {
        errorCode = GetLastError();
        goto Exit;
    }

    processId = procInfo.dwProcessId;

Exit:

    SetLastError(errorCode);
    return processId;
}


/*++

Routine Name:

    ihiInitInjectionData

Routine Description:

    Initialize the data which is injected into the target
    process before we create a remote thread in it. This
    data is used by our injector DLL's patching function

Return:

    true    - represent success
    false   - represent failure

--*/
VOID
ihiInitInjectionData(LPCWSTR inDllPath, PVOID inLoadContext,
                     ULONG inLoadContextSize, PINJECTION_DATA *outInjData,
                     PULONG outInjDataSize)
{
    PINJECTION_DATA injData;
    ULONG injDataSize;

    injDataSize = sizeof(INJECTION_DATA) + inLoadContextSize;
    injData = (PINJECTION_DATA)malloc(injDataSize);
    if (injData == NULL)
    {
        goto Exit;
    }
    memset(injData, 0, injDataSize);

    HMODULE hModule = GetModuleHandleA("kernel32.dll");
    if (hModule == NULL)
    {
        goto Exit;
    }

    PVOID loadLibraryW = GetProcAddress(hModule, "LoadLibraryW");
    if (loadLibraryW == NULL)
    {
        goto Exit;
    }
    injData->mLoadLibraryW = loadLibraryW;

    PVOID getProcAddr = GetProcAddress(hModule, "GetProcAddress");
    if (getProcAddr == NULL)
    {
        goto Exit;
    }
    injData->mGetProcAddr = getProcAddr;

    PVOID freeLibrary = GetProcAddress(hModule, "FreeLibrary");
    if (freeLibrary == NULL)
    {
        goto Exit;
    }
    injData->mFreeLibrary = freeLibrary;

    PVOID getModuleHandle = GetProcAddress(hModule, "GetModuleHandleW");
    if (getModuleHandle == NULL)
    {
        goto Exit;
    }
    injData->mGetModuleHandleW = getModuleHandle;

    PVOID deleteFile = GetProcAddress(hModule, "DeleteFileW");
    if (deleteFile == NULL)
    {
        goto Exit;
    }
    injData->mDeleteFileW = deleteFile;

    PVOID sleep = GetProcAddress(hModule, "Sleep");
    if (sleep == NULL)
    {
        goto Exit;
    }
    injData->mSleep = sleep;

    strcpy((LPSTR) injData->mLoadFnName, "IhSerumLoad");
    strcpy((LPSTR) injData->mUnloadFnName, "IhSerumUnload");
    strcpy((LPSTR) injData->mGetRefFnName, "IhSerumGetRefCount");
    wcscpy(injData->mDllName, inDllPath);

    injData->mLoadContextSize = inLoadContextSize;
    if (inLoadContextSize > 0)
    {
        memcpy(injData + 1, inLoadContext, inLoadContextSize);
    }

    *outInjData = injData;
    *outInjDataSize = injDataSize;

Exit:
    return;
}



/*++

Routine Name:

    IhuInjectDll

Routine Description:

    Inject a DLL into a running process by calling
    CreateRemoteThread

Return:

    true    - represent success
    false   - represent failure

    In case of failure, please call GetLastError for
    more information.

--*/
bool WINAPI
IhuInjectDll(HANDLE hProcess, LPCWSTR inDllPath, PVOID inLoadContext,
             ULONG inLoadContextSize)
{
    LPVOID pInjectionData;
    LPVOID pInjectionCode;
    SIZE_T notUsed;
    bool funcResult;
    PINJECTION_DATA injData;
    ULONG injDataSize;

    funcResult = false;

    ihiInitInjectionData(inDllPath, inLoadContext, inLoadContextSize,
                         &injData, &injDataSize);
    if (injData == NULL)
    {
        goto Exit;
    }
    
    pInjectionData = VirtualAllocEx(hProcess, NULL, injDataSize, MEM_COMMIT,
                                    PAGE_READWRITE);
    if (pInjectionData == NULL)
    {
        goto Exit;
    }

    WriteProcessMemory(hProcess, pInjectionData, injData, injDataSize,
                       &notUsed);

    ULONG codeSize = 0;
    codeSize = (DWORD_PTR) ihiInjectedCodeEnd - (DWORD_PTR) ihiInjectedCode;

    pInjectionCode = VirtualAllocEx(hProcess, NULL, codeSize, MEM_COMMIT,
                                    PAGE_EXECUTE_READWRITE);
    if (pInjectionCode == NULL)
    {
        goto Exit;
    }

    WriteProcessMemory(hProcess, pInjectionCode, ihiInjectedCode, codeSize,
                       &notUsed);

    DWORD threadId = 0;
    HANDLE hThread = CreateRemoteThread(hProcess, 0, 0,
                                        (LPTHREAD_START_ROUTINE)pInjectionCode,
                                        pInjectionData, 0, &threadId);
    if (hThread)
    {
        funcResult = true;
    }

Exit:

    if (injData != NULL)
    {
        free(injData);
    }

    return funcResult;
}



bool WINAPI
IhuUninjectDll(HANDLE hProcess, LPCWSTR inDllPath)
/*++

Routine Description:

    This routine removes an already injected DLL from the process

Arguments:

    hProcess - Handle to the process with injected DLL
    inDllPath - Path of the injected DLL to be removed

--*/
{
    LPVOID pInjectionData;
    LPVOID pInjectionCode;
    SIZE_T notUsed;
    bool funcResult;
    PINJECTION_DATA injData;
    ULONG injDataSize;

    funcResult = false;

    ihiInitInjectionData(inDllPath, NULL, 0, &injData, &injDataSize);
    if (injData == NULL)
    {
        goto Exit;
    }

    pInjectionData = VirtualAllocEx(hProcess, NULL, sizeof(injData), MEM_COMMIT,
                                    PAGE_READWRITE);
    if (pInjectionData == NULL)
    {
        goto Exit;
    }

    WriteProcessMemory(hProcess, pInjectionData, injData, injDataSize,
                       &notUsed);

    ULONG codeSize = 0;
    codeSize = (DWORD_PTR) ihiUnloadCodeEnd - (DWORD_PTR) ihiUnloadCode;

    pInjectionCode = VirtualAllocEx(hProcess, NULL, codeSize, MEM_COMMIT,
                                    PAGE_EXECUTE_READWRITE);
    if (pInjectionCode == NULL)
    {
        goto Exit;
    }

    WriteProcessMemory(hProcess, pInjectionCode, ihiUnloadCode, codeSize,
                       &notUsed);

    DWORD threadId = 0;
    HANDLE hThread = CreateRemoteThread(hProcess, 0, 0,
                                        (LPTHREAD_START_ROUTINE)pInjectionCode,
                                        pInjectionData, 0, &threadId);
    if (hThread)
    {
        funcResult = true;
    }

Exit:

    if (injData != NULL)
    {
        free(injData);
    }

    return funcResult;
}


//
// Turn off optimizations here because they can cause problem with
// our injection code which shouldn't be optimized without our knowledge
//
#pragma optimize("g", off)


/*++

Routine Name:

    ihiInjectedCode

Routine Description:

    This function is actually injected in the target process
    and it executes in the context of target process. It
    first loads our injector DLL in target process and then
    calls its patching initiate function to patch the IAT
    of target process.

Return:

    none

--*/
static void
ihiInjectedCode(LPVOID * inAddress)
{
    HMODULE hMod;

    //
    // This is a loop that can help debugging the injected code, by spinning
    // in a tight loop, until a debugger is attached to the target process
    // and eax is set to 1 to exit the loop.
    //
    // NOTE: Change eax to 0 and recompile to debug.
    //
    _asm push eax;
    _asm mov eax, 1;
debug:
    _asm cmp eax, 0;
    _asm je debug;
    _asm pop eax;

    // 
    // This function cannot make direct function calls because it is
    // injected in target process by calling WriteProcessMemory and
    // if we use any direct function calls, its address in new process
    // may not be correct. Hence, we use function pointers only. This is
    // safe _ONLY_ because kernel32.dll is loaded at same address in all
    // the modules.
    // 

    PINJECTION_DATA injData = (INJECTION_DATA *)inAddress;
    PFNLOADLIBRARY pfnLoadLibrary = (PFNLOADLIBRARY)injData->mLoadLibraryW;

    hMod = pfnLoadLibrary(injData->mDllName);
    if (hMod)
    {
        PFNGETPROCADDRESS pfnGetProcAddress =
            (PFNGETPROCADDRESS) injData->mGetProcAddr;

        PFNSERUMLOAD pfnSerumLoad =
            (PFNSERUMLOAD) pfnGetProcAddress(hMod,
                                             (LPCSTR) injData->mLoadFnName);
        if (pfnSerumLoad != NULL)
        {
            pfnSerumLoad(injData + 1, injData->mLoadContextSize);
        }
    }
}


/*++

Routine Name:

    ihiInjectedCodeEnd

Routine Description:

    This is just a dummy function and is required in
    ihiInjectedCode function's size calculation

--*/
static void
ihiInjectedCodeEnd()
{
    bool unused;
    unused = true;
}



/*++

Routine Name:

    ihiUnloadCode

Routine Description:

    This function is actually injected in the target process
    and it executes in the context of target process. It simply
    tries to unload our DLL from the target process

Return:

    none

--*/
static void
ihiUnloadCode(LPVOID * inAddress)
{
    HMODULE hMod;

    _asm push eax;
    _asm mov eax, 1;
debug:
    _asm cmp eax, 0;
    _asm je debug;
    _asm pop eax;

    // 
    // This function cannot make direct function calls
    // because it is injected in target process by calling
    // WriteProcessMemory and if we use any direct function
    // calls, its address in new process may not be correct.
    // Hence, we use function pointers only. This is *ONLY*
    // safe because kernel32.dll is loaded at same address
    // in all the modules
    // 
    INJECTION_DATA *injData = (INJECTION_DATA *) inAddress;

    PFNGETMODULEHANDLE pfnGetModuleHandle =
        (PFNGETMODULEHANDLE) injData->mGetModuleHandleW;

    hMod = pfnGetModuleHandle(injData->mDllName);

    if (hMod)
    {
        PFNGETPROCADDRESS pfnGetProcAddress =
            (PFNGETPROCADDRESS) injData->mGetProcAddr;

        PFNFREELIBRARY pfnFreeLibrary =
            (PFNFREELIBRARY) injData->mFreeLibrary;

        PFNSLEEP pfnSleep = (PFNSLEEP) injData->mSleep;

        PFNSERUMUNLOAD pfnSerumUnload =
            (PFNSERUMUNLOAD) pfnGetProcAddress(hMod,
                                               (LPCSTR)injData->mUnloadFnName);

        PFNSERUMGETREFCOUNT pfnSerumGetRefCount =
            (PFNSERUMGETREFCOUNT) pfnGetProcAddress(hMod,
                                                    (LPCSTR) injData->mGetRefFnName);
        if (pfnSerumUnload != NULL)
        {
            pfnSerumUnload();

            while (true)
            {
                if (pfnSerumGetRefCount() == 0)
                {
                    if (!pfnFreeLibrary(hMod))
                    {
                        pfnFreeLibrary(hMod);
                    }

                    break;
                }
                else
                {
                    pfnSleep(500);
                }
            }
        }
    }
    else
    {
        // Issue error here and bail out
    }

    PFNDELETEFILE deleteFile = (PFNDELETEFILE) injData->mDeleteFileW;
    if (!deleteFile(injData->mDllName))
    {
        // Issue error here and bail out
    }
}


/*++

Routine Name:

    ihiUnloadCodeEnd

Routine Description:

    This is just a dummy function and is required in
    ihiUnloadCode function's size calculation

--*/
static void
ihiUnloadCodeEnd(void)
{
    bool unused;
    unused = false;
}

#pragma optimize( "g", on)

#endif // defined(_M_IX86)
