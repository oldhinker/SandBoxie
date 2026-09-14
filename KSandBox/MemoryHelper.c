#include "MemoryHelper.h"
#include "MemoryPool.h"

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
        NtAllocateVirtualMemory(NtCurrentProcess(), &v5, 0,
            &RegionSize, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
            ((UCHAR)tag == 0xFF ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE));
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




void* AllocateMemoryEx(POOL* Pool, ULONG ViewSize, BOOLEAN Tag)
{

#ifdef DEBUG_MEMORY

    UCHAR* v5 = MemoryPoolAllocate(Pool, ViewSize + 64 * 2);
    if (ptr) {

        memset(ptr, 0xCC, 64);
        ptr += 64;
        memset(ptr + size, 0xCC, 64);
    }

#else ! DEBUG_MEMORY

    void* v5 = MemoryPoolAllocate(Pool, ViewSize);

#endif DEBUG_MEMORY

    // We can't log memory failures because the log functions alloc mem and we will get into a recursive loop
    //if (! ptr) {

    //    if (InitMsg) {

    //        Log_Msg0(MSG_1104);

    //    } else {

    //        Log_Msg_Session(MSG_1201, NULL, NULL, -1);
    //    }
    //}

    return v5;
}
void FreeMemoryEx(void* VirtualAddress, ULONG ViewSize)
{
    if (VirtualAddress && ViewSize) {

#if POOL_DEBUG
        ULONG v7 = ViewSize;
        ViewSize += sizeof(ULONG);
        if (*(ULONG*)((UCHAR*)VirtualAddress + v7) != ViewSize) {
            // printf("got %d (at %08X), expected %d for %08X\n", *(ULONG *)((UCHAR *)ptr + caller_size), (ULONG *)((UCHAR *)ptr + caller_size), size, ptr);
            ABEND(FREE_SIZE_MISMATCH);
        }
#endif

        // if the pointer is page-aligned, this must be a LARGE_CHUNK
        if (((ULONG_PTR)VirtualAddress & (POOL_PAGE_SIZE - 1)) == 0)
            FreeLargeChunk(VirtualAddress, ViewSize);
        else
            FreeCells(VirtualAddress, NUM_CELLS(ViewSize));

#if 0
#if defined(KERNEL_MODE)
       
#endif
#endif

    }
    else
        ABEND(FREE_NULL_PTR_OR_ZERO_SIZE);
}

WCHAR* AllocateStringEx(
    POOL* Pool, const WCHAR* StringData, BOOLEAN Tag)
{
    WCHAR* v5;
    ULONG v7 = (wcslen(StringData) + 1) * sizeof(WCHAR);
    v5 = AllocateMemoryEx(Pool, v7, Tag);
    if (v5)
        memcpy(v5, StringData, v7);
    return v5;
}


//向Ring3拷贝数据
void CopyStringToUser(
    UNICODE_STRING64* StringData, WCHAR* BufferData, size_t DataLength)
{
    if (StringData) {
        ProbeForRead(StringData, sizeof(UNICODE_STRING64), sizeof(ULONG_PTR));
        ProbeForWrite(StringData, sizeof(UNICODE_STRING64), sizeof(ULONG_PTR));
        if (DataLength > StringData->MaximumLength)
            ExRaiseStatus(STATUS_BUFFER_TOO_SMALL);
        else {
            WCHAR* Buffer = (WCHAR*)StringData->Buffer;
            ProbeForWrite(Buffer, DataLength, sizeof(WCHAR));
            if (DataLength) {
                memcpy(Buffer, BufferData, DataLength);
                StringData->Length = (USHORT)DataLength - sizeof(WCHAR);
            }
            else
                StringData->Length = 0;
        }
    }
}