#pragma once
#include "Common.h"
#include "MemoryHelper.h"
#include "ProcessHelper.h"

#define NATIVE_FUNCTION_NAMES   { "NtDelayExecution", "NtDeviceIoControlFile", "NtFlushInstructionCache", "NtProtectVirtualMemory" }
#define NATIVE_FUNCTION_COUNT   4
#define NATIVE_FUNCTION_SIZE    32



struct _SYSCALL_ENTRY_;
typedef struct _SYSCALL_ENTRY_ SYSCALL_ENTRY,*PSYSCALL_ENTRY;


typedef NTSTATUS(*LPFN_SYSCALLHANDLER1)(
    PROCESS* Process, PSYSCALL_ENTRY SyscallEntry, ULONG_PTR* ParameterData);


typedef NTSTATUS(*LPFN_SYSCALLHANDLER2)(
    PROCESS* Process, void* Object, UNICODE_STRING* Name,
    ULONG Operation, ACCESS_MASK GrantedAccess);

#ifdef _M_AMD64
typedef BOOLEAN(*LPFN_SYSCALLHANDLER3)(
    PROCESS* Process, SYSCALL_ENTRY* SyscallEntry, ULONG_PTR* ParameterData);
#endif

struct _SYSCALL_ENTRY_ {

    NODE Node;
    USHORT ServiceIndex;
    USHORT ParameterCount;
    ULONG  ServiceOffset;
    void*  ServiceAddress;
    LPFN_SYSCALLHANDLER1 SyscallHandler1;
    LPFN_SYSCALLHANDLER2 SyscallHandler2;
#ifdef _M_AMD64
    LPFN_SYSCALLHANDLER3 SyscallHandler3;
#endif
    UCHAR disabled;
    UCHAR approved;
    USHORT NameLength;
    UCHAR  ServiceName[1];

};

extern LIST __SyscallsList;
extern UCHAR* __SyscallsCode;

BOOLEAN GetSystemServiceInfo(void);
ULONG GetSystemServiceIndex(UCHAR* ServiceAddress);
BOOLEAN GetSystemServiceAddress(ULONG ServiceIndex, void** ServiceAddress, ULONG* ParameterCount);
void* GetSystemServiceTableInternal(void);

BOOLEAN GetSystemServiceCode(void);
SYSCALL_ENTRY* GetSyscallEntry(const UCHAR* ServiceName);