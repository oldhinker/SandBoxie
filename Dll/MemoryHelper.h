#pragma once
#include "Common.h"


BOOL InitializeMemory();
void* AllocateMemory(ULONG ViewSize, ULONG Tag);
void FreeMemory(void* VirtualAddress, ULONG Tag);












#define NtCurrentProcess() ( (HANDLE) -1 )

typedef
NTSTATUS(NTAPI* LPFN_NTALLOCATEVIRTUALMEMORY)(IN HANDLE ProcessHandle,
    IN OUT PVOID* UBaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T URegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect);

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation
} MEMORY_INFORMATION_CLASS;
typedef NTSTATUS(*LPFN_NTQUERYVIRTUALMEMORY)(
    IN  HANDLE ProcessHandle,
    IN  PVOID BaseAddress,
    IN  MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN  SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL);


#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllimport) NTSTATUS __stdcall NtQueryVirtualMemory(
    IN  HANDLE ProcessHandle,
    IN  PVOID BaseAddress,
    IN  MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN  SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength);
__declspec(dllimport) NTSTATUS __stdcall NtAllocateVirtualMemory(
    IN  HANDLE ProcessHandle,
    PVOID* BaseAddress,
    IN  ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    IN  ULONG AllocationType,
    IN  ULONG Protect);
#ifdef __cplusplus
}
#endif






