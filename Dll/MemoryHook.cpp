#include "MemoryHook.h"
#include "StatusHelper.h"
#include "StringHelper.h"
#include "StatusHelper.h"
#include "ThreadHelper.h"
#include "MemoryPool.h"
#include "ObjectHelper.h"
LPFN_NTQUERYVIRTUALMEMORY   __sys_NtQueryVirtualMemory = NULL;

NTSTATUS  DetourNtQueryVirtualMemory(
    HANDLE ProcessHandle,
    void* BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    void* MemoryInformation,
    SIZE_T Length,
    SIZE_T* ResultLength)
{

    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING* Name;
    ULONG NameType;
    ULONG LastError;
    SIZE_T MaxLength;
    SIZE_T ReturnLength;
    THREAD_DATA* ThreadData = GetTlsData(&LastError);   //线程 存储


    if (MemoryInformationClass != MemoryMappedFilenameInformation) {

        //白名单放行处理
        return __sys_NtQueryVirtualMemory(
            ProcessHandle, BaseAddress, MemoryInformationClass,
            MemoryInformation, Length, ResultLength);
    }



    if (Length) {
        Name = (UNICODE_STRING*)MemoryInformation;
        MaxLength = Length & ~1;
    }
    else {
        MaxLength = sizeof(OBJECT_NAME_INFORMATION) + 32;
        Name = (UNICODE_STRING*)MemoryPoolAllocateEx(__Pool10,(ULONG)MaxLength);
    }

    Status = __sys_NtQueryVirtualMemory(
        ProcessHandle, BaseAddress, MemoryMappedFilenameInformation,
        Name, MaxLength, &ReturnLength);

    if (Status == STATUS_INFO_LENGTH_MISMATCH ||
        Status == STATUS_BUFFER_OVERFLOW) {

        if (Name != MemoryInformation)
            MemoryPoolFreeEx(Name);
        MaxLength = ReturnLength;
        Name = (UNICODE_STRING*)MemoryPoolAllocateEx(__Pool10,(ULONG)MaxLength);

        Status = __sys_NtQueryVirtualMemory(
            ProcessHandle, BaseAddress, MemoryMappedFilenameInformation,
            Name, MaxLength, &ReturnLength);
    }


    if (!NT_SUCCESS(Status)) {

        if (Name != MemoryInformation)
            MemoryPoolFreeEx(Name);

        Status = __sys_NtQueryVirtualMemory(
            ProcessHandle, BaseAddress, MemoryInformationClass,
            MemoryInformation, Length, ResultLength);

        goto Exit;
    }
    if (Name->Length && MaxLength < 0x01000000) {

    
        //过滤处理
    }

    if (ResultLength)
        *ResultLength = ReturnLength;

    if (Length < ReturnLength) {

        if (Length < sizeof(UNICODE_STRING))
            Status = STATUS_INFO_LENGTH_MISMATCH;
        else
            Status = STATUS_BUFFER_OVERFLOW;

    }
    else if (Name != MemoryInformation) {

        //返回数据
        UNICODE_STRING* v1 = (UNICODE_STRING*)MemoryInformation;
        memcpy(v1, Name, ReturnLength);
        v1->Buffer = (WCHAR*)(v1 + 1);
    }

    if (Name != MemoryInformation)
        MemoryPoolFreeEx(Name);

Exit:
    SetLastError(LastError);
    return Status;
}