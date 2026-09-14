#include "MemoryHelper.h"
#include "_tWinMain.h"

LPFN_NTALLOCATEVIRTUALMEMORY __NtAllocateVirtualMemory = NULL;
BOOLEAN InitializeMemory(void)
{
    if (__Ntdll == NULL)
    {
        __Ntdll = GetModuleHandle(_T("ntdll.dll"));
    }
    __NtAllocateVirtualMemory = (LPFN_NTALLOCATEVIRTUALMEMORY)GetProcAddress(__Ntdll, "NtAllocateVirtualMemory");


    if (!__NtAllocateVirtualMemory)
        return false;
}