#include "MemoryHelper.h"
#include "dllmain.h"
#include "MemoryPool.h"
#include "ThreadHelper.h"

LPFN_NTALLOCATEVIRTUALMEMORY __NtAllocateVirtualMemory = NULL;




BOOL InitializeMemory()
{
   



    if (__Ntdll == NULL)
    {
        __Ntdll = GetModuleHandle(_T("ntdll.dll"));
    }
    __NtAllocateVirtualMemory = (LPFN_NTALLOCATEVIRTUALMEMORY)GetProcAddress(__Ntdll, "NtAllocateVirtualMemory");




    if (!__NtAllocateVirtualMemory)
        return false;


    if (!__Pool) {
        __Pool = CreateMemoryPoolWithTagged(POOL_TAG);
        if (!__Pool)
            return FALSE;
    }

    if (!__Pool10) {
        __Pool10 = CreateMemoryPoolWithTagged(POOL_TAG);
        if (!__Pool10)
            return FALSE;
    }
    //线程局部存储
    if (__TlsIndex == TLS_OUT_OF_INDEXES) {
        __TlsIndex = TlsAlloc();
        if (__TlsIndex == TLS_OUT_OF_INDEXES)
            return FALSE;
    }

    return TRUE;
}



void* AllocateMemory(ULONG ViewSize, ULONG Tag)
{
    void* v5 = NULL;

    // size parameter will be a multiple of POOL_PAGE_SIZE, and this routine
    // must return memory allocated with page-alignment
#ifdef KERNEL_MODE
#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
    v5 = ExAllocatePool2(POOL_FLAG_PAGED, ViewSize, Tag);
#else
    v5 = ExAllocatePoolWithTag(PagedPool, ViewSize, Tag);   //数据段分页内存
#endif
#else
    SIZE_T RegionSize = ViewSize;
#ifdef _M_ARM64EC
    if ((UCHAR)Tag == 0xEC) {

        //
        // this pool is designated for native ARM code in a EC process
        //
        MEM_EXTENDED_PARAMETER Parameter = { 0 };
        Parameter.Type = MemExtendedParameterAttributeFlags;
        Parameter.ULong64 = MEM_EXTENDED_PARAMETER_EC_CODE;

        __sys_NtAllocateVirtualMemoryEx(NtCurrentProcess(), &v5, &RegionSize,
            MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
            PAGE_EXECUTE_READWRITE, &Parameter, 1);
    }
    else
#endif
        __NtAllocateVirtualMemory(NtCurrentProcess(), &v5, 0,
            &RegionSize, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
            ((UCHAR)Tag == 0xFF ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE));
#endif
    // printf("Allocated %d bytes at %08X\n", size, ptr);
    return v5;
}

void FreeMemory(void* VirtualAddress, ULONG Tag)
{
    // printf("Freeing at %08X\n", ptr);
#ifdef KERNEL_MODE
    ExFreePoolWithTag(VirtualAddress, Tag);
#else
    if (!VirtualFree(VirtualAddress, 0, MEM_RELEASE)) {
        RaiseException(
            STATUS_ACCESS_VIOLATION,
            EXCEPTION_NONCONTINUABLE_EXCEPTION, 0, NULL);
        ExitProcess(-1);
    }
#endif
}




