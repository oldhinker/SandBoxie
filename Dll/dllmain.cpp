// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "dllmain.h"
#include "MemoryHelper.h"
#include "FileHelper.h"
#include "HookHelper.h"
#include "StringHelper.h"

HMODULE  __Ntdll = NULL;
ULONG    __Windows = 0;
HINSTANCE __Instance = NULL;


const WCHAR* __BoxIpcPathData = NULL;
ULONG __BoxIpcPathLength = 0;
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
     


        if (GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrFastFailInLoaderCallout"))
            __Windows = 10;
        else //if (GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlpcConnectPortEx")) 
            __Windows = 8;

        InitializeGeneric(hModule);
        InitializeModuleHook();
       
        InitializeFile();

       
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void InitializeGeneric(HINSTANCE Instance)
{
    //
    // Dll_InitGeneric initializes SbieDll in a general way, suitable
    // for a program which may or may not be in the sandbox
    //

    __Instance = Instance;

    __Ntdll = GetModuleHandle(_T("ntdll.dll"));




    InitializeMemory();
    InitializeString();
   
 
}


