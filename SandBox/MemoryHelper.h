#pragma once
#include "Common.h"


typedef 
NTSTATUS (__stdcall *LPFN_NTALLOCATEVIRTUALMEMORY)(
    IN  HANDLE ProcessHandle,
    PVOID* BaseAddress,
    IN  ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    IN  ULONG AllocationType,
    IN  ULONG Protect);

BOOLEAN InitializeMemory(void);


extern LPFN_NTALLOCATEVIRTUALMEMORY __NtAllocateVirtualMemory;
