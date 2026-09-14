#pragma once
#include "Common.h"
#include "LowLevel.h"

typedef NTSTATUS(*lpfn_NtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);




void WriteMemorySafe(DATA_INFO* DataInfo, void* VirtualAddress, SIZE_T ViewSize, void* BufferData);