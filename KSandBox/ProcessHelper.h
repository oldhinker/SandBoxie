#pragma once
#include "Common.h"
#include "MemoryPool.h"
#include "MemoryList.h"
#include "Box.h"

typedef struct _PROCESS_  PROCESS, *PPROCESS;

#define IS_ARG_CURRENT_PROCESS(Handle) ((ULONG)Handle == 0xffffffff)   

#ifdef _WIN64
#define PROCESS_TERMINATED      ((PROCESS *) 0xFFFFFFFFFFFFFFFF)
#else
#define PROCESS_TERMINATED      ((PROCESS *) 0xFFFFFFFF)
#endif


/*
#define PROCESS_TERMINATE         (0x0001)
#define PROCESS_CREATE_THREAD     (0x0002)
#define PROCESS_SET_SESSIONID     (0x0004)
#define PROCESS_VM_OPERATION      (0x0008)
#define PROCESS_VM_READ           (0x0010)
#define PROCESS_VM_WRITE          (0x0020)
#define PROCESS_DUP_HANDLE        (0x0040)
#define PROCESS_CREATE_PROCESS    (0x0080)
#define PROCESS_SET_QUOTA         (0x0100)
#define PROCESS_SET_INFORMATION   (0x0200)
#define PROCESS_QUERY_INFORMATION (0x0400)
#define PROCESS_SUSPEND_RESUME    (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)     // vista
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)
#if (NTDDI_VERSION >= NTDDI_VISTA)
#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0xFFFF)
#else
#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0xFFF)
#endif
*/


NTOS_NTSTATUS
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);


NTOS_API(ULONG) PsGetProcessSessionId(PEPROCESS EProcess);

NTOS_API(ULONG_PTR) PsGetProcessPeb(PEPROCESS EProcess);



struct _PROCESS_ {

#ifndef USE_PROCESS_MAP
    NODE Node;
#endif

    HANDLE ProcessIdentity;
    POOL*  Pool;
    BOX* Box;
    ULONG64 CreateTime;
    volatile BOOLEAN IsInitialized;
    volatile BOOLEAN IsTerminated;        // process termination started?
    volatile ULONG   Reason;
    BOOLEAN IsLowLevelLoaded;                 //LowLevel是否被注入
    BOOLEAN IsDllLoaded;                     //Dll是否已经被注入





    BOOLEAN IsHostInject;
};



BOOLEAN InitializeProcess(void);
void UninitializeProcess(BOOLEAN FreeLock);

void GetProcessName(
    POOL* Pool, ULONG_PTR ProcessIdentity,
    void** VirtualAddress, ULONG* ViewSize, WCHAR** out_ptr);


//
PROCESS* CreateProcess(
    HANDLE ProcessIdentity, const void* Box, const WCHAR* ImagePath,
    KIRQL* Irql);

void CreateTerminated(HANDLE ProcessIdentity, ULONG SessionIdentity);

PROCESS* FindProcess(HANDLE ProcessIdentity, KIRQL* Irql);

void DeleteProcess(HANDLE ProcessIdentity);

void SetTerminated(PROCESS* Process, ULONG Reason);


NTSTATUS EnumerateProcess(
    const WCHAR* BoxName, BOOLEAN IsAllSessions, ULONG SessionIdentity,
    ULONG* ProcessIdentitys, ULONG* Count);
NTSTATUS GetSessionIdentity(ULONG* SessionIdentity);

PEPROCESS GetProcessObject(
    HANDLE ProcessIdentity, UNICODE_STRING* SidString, ULONG* SessionIdentity);

NTSTATUS QuerySidString(
    void* TokenObject, UNICODE_STRING* SidString);

BOOLEAN IsProcessRunningAsSystemAccount(HANDLE ProcessIdenity);

NTSTATUS GetSidStringAndSessionIdentity(
    HANDLE ProcessHandle, HANDLE ProcessIdentity,
    UNICODE_STRING* SidString, ULONG* SessionIdentity);

void GetCurrentDirectory(
    PEPROCESS ProcessObject, WCHAR** CurrentDirectory, ULONG* DirectoryLength);


void GetStringFromPeb(
    PEPROCESS ProcessObject, ULONG Offset, ULONG MaxLength,
    WCHAR** OutBuffer, ULONG* OutLength);


void GetDocArgument(
    PEPROCESS ProcessObject, WCHAR** DocArgument, ULONG* ArgumentLength);

extern PERESOURCE __ProcessListLock;