#pragma once
#include "Common.h"
#include "MemoryHelper.h"


extern LPFN_NTQUERYVIRTUALMEMORY   __sys_NtQueryVirtualMemory;

NTSTATUS  DetourNtQueryVirtualMemory(
    HANDLE ProcessHandle,
    void* BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    void* MemoryInformation,
    SIZE_T Length,
    SIZE_T* ResultLength);