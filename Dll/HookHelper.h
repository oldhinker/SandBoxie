#pragma once
#include "Common.h"
#include "HookHelper.h"
#include "MemoryPool.h"
#include "MemoryList.h"


#ifdef _WIN64

typedef struct _VECTOR_TABLE {

    NODE   Node;

    void* Offset;
    int Index;
    int MaxEntries;
} VECTOR_TABLE;

#define VTABLE_SIZE 0x4000 //16k enough for 2048 8 byte entries

#endif _WIN64


typedef struct _MODULE_HOOK {

    NODE   Node;

    HMODULE     Module;
#ifdef _M_ARM64EC
    ULONG       tag;
#endif
    POOL* Pool;
#ifdef _WIN64
    LIST        VTables;
#endif
    LIST        Trace;
} MODULE_HOOK;










void InitializeModuleHook();
void* ModuleHook(
    const char* SeviceName, void* ServiceAddress, void* DetourAddress, HMODULE Module);

void* InstallModuleHook(
    const char* SeviceName, void* ServiceAddress, void* DetourAddress, HMODULE Module, DWORD* HookStats);

void* InstallModuleHookInternal(
    const char* SeviceName, void* ServiceAddress, void* DetourAddress, HMODULE Module);

void UninstallModuleHook(HMODULE Module);

MODULE_HOOK* GetModuleHookInfo(HMODULE Module, ULONG Tag);
void FreeHookModuleInfo(void* ModuleHook);

LONG CreateModuleHookTrampoline(void* ServiceAddress, void* Trampoline);


#define DLL_HOOK(Pfx,Service)                  \
    *(ULONG_PTR *)&__sys_##Service = (ULONG_PTR)   \
        ModuleHook(#Service, Service, Pfx##Service, ModuleHandle);   \
    if (! __sys_##Service) return FALSE;



#ifdef _WIN64
VECTOR_TABLE* GetHookTable(MODULE_HOOK* ModuleHook, ULONG_PTR TargetAddress, __int64 MaxDelta, BOOLEAN LongRange);
#endif _WIN64
