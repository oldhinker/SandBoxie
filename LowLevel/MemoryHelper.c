#include "MemoryHelper.h"
#include "LowLevel.h"

void WriteMemorySafe(DATA_INFO* DataInfo, void* VirtualAddress, SIZE_T ViewSize, void* BufferData)
{
    void* BaseAddress = VirtualAddress;
    SIZE_T RegionSize = ViewSize;
    ULONG OldProtect;


    CALL(NtProtectVirtualMemory)(
        NtCurrentProcess(), &BaseAddress, &RegionSize,
        PAGE_EXECUTE_READWRITE, &OldProtect);

    /*
    0:000> u 00000000`000304c9
    00000000`000304c9 4c8bd1          mov     r10,rcx
    00000000`000304cc b84d000000      mov     eax,4Dh
    00000000`000304d1 0f05            syscall
    00000000`000304d3 c3              ret
    */



    // memcopy is not available, lets do our own
    switch (ViewSize) {
    case 1: *(UCHAR*)VirtualAddress = *(UCHAR*)BufferData;       break;
    case 2: *(USHORT*)VirtualAddress = *(USHORT*)BufferData;     break;
    case 4: *(ULONG*)VirtualAddress = *(ULONG*)BufferData;       break;
    case 8: *(ULONG64*)VirtualAddress = *(ULONG64*)BufferData;   break;
    default:
        for (SIZE_T i = 0; i < ViewSize; i++)
            ((UCHAR*)VirtualAddress)[i] = ((UCHAR*)BufferData)[i];
    }

    CALL(NtProtectVirtualMemory)(
        NtCurrentProcess(), &BaseAddress, &RegionSize,
        OldProtect, &OldProtect);
}