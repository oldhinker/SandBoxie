#pragma once
#include "Common.h"
#include "StringHelper.h"

typedef struct _MY_TARGETS 
{
	unsigned long long Start;
	unsigned long long DataInfo;
	unsigned long long DetourCode;
} MY_TARGETS;



typedef struct _PROCESS_MESSAGE_
{

    ULONG ProcessIdentity;
    ULONG SessionIdentity;
    ULONG64 CreateTime;
    BOOLEAN IsWow64;
    BOOLEAN add_to_job;
    BOOLEAN IsHostInject;
    ULONG reason;
    WCHAR ImageName[64];

}PROCESS_MESSAGE, *PPROCESS_MESSAGE;;




#ifdef _WIN64

typedef struct _JUMP_TABLE_ENTRY
{
#ifdef _M_ARM64
    //  unsigned char code[0x28]; //for jtable with hotpatch location for sboxdll hooking
    unsigned char Code[0x20]; //for jtable
#else
    //  unsigned char code[0x18]; //for jtable with hotpatch location for sboxdll hooking
    unsigned char Code[0x10]; //for jtable
#endif
}JUMP_TABLE_ENTRY;

typedef struct _JUMP_TABLE_
{
    JUMP_TABLE_ENTRY JumpTableEntry[1024];
}JUMP_TABLE;

#endif


typedef struct _INJECT_DATA {

    ULONG64 DataInfo;           // 0

    ULONG64 RtlFindActCtx;          // 8
    ULONG RtlFindActCtx_Protect;
    UCHAR RtlFindActCtx_Bytes[20];

    ULONG64 LdrLoadDll;
    ULONG64 LdrGetProcAddr;
    ULONG64 NtProtectVirtualMemory;
    ULONG64 NtRaiseHardError;
    ULONG64 NtDeviceIoControlFile;
    ULONG64 api_device_handle;

    UNIVERSAL_STRING KernelDll;
    UNIVERSAL_STRING SbieDll;

} INJECT_DATA;



ULONG InjecitonPrepare();

ULONG InjecitonPrepareInternal(BOOLEAN IsWow64, void** TextAddress, ULONG* TextLength,
    ULONG* StartOffset, ULONG* DataInfoOffset, ULONG* DetourCodeOffset);


ULONG InjectProcess(HANDLE ProcessHandle, ULONG Flags, BOOLEAN IsDuplicateHandle);

void* AllocateRemoteMemory(HANDLE ProcessHandle, SIZE_T ViewSize, BOOLEAN IsExecutable
#ifdef _M_ARM64
#endif
);

void* CopyShellCode(HANDLE ProcessHandle, SIZE_T ViewSize, SIZE_T TestLength, const void* TestAddress
#ifdef _M_ARM64
#endif
);
HANDLE CopyDeviceHandle(HANDLE ProcessHandle);

#ifdef _WIN64
BOOLEAN Has32BitJumpHorizon(void* Target, void* Detour);
#endif


BOOLEAN BuildTrampoline(
    BOOLEAN Diff, UCHAR* ShellCode, ULONG_PTR VirtualAddress
#ifdef _M_ARM64
#endif
);

void* CopySyscalls(HANDLE ProcessHandle, BOOLEAN IsWow64
#ifdef _M_ARM64
    , BOOLEAN use_arm64ec
#endif
);

BOOLEAN CopyData(
    HANDLE ProcessHandle, void* VirtualAddress, void* BufferData);


BOOLEAN WriteJump(HANDLE ProcessHandle, void* VirtualAddress, BOOLEAN Diff
#ifdef _M_ARM64
    , BOOLEAN use_arm64ec
#endif
);