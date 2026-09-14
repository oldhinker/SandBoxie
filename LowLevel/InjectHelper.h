#pragma once
#include <Windows.h>
#include <tchar.h>
#include "LowLevel.h"
#include "StringHelper.h"

typedef NTSTATUS(*LPFN_LDRLOADDLL)(
    WCHAR* PathString, ULONG* DllFlags,
    UNICODE_STRING* ModuleName, HANDLE* ModuleHandle);

typedef NTSTATUS(*LPFN_LDRGETPROCEDUREADDRESS)(
    HANDLE ModuleHandle, ANSI_STRING* ServiceName, ULONG ServiceIndex,
    ULONG_PTR* ServiceAddress);


typedef NTSTATUS(*LPFN_NTRAISEHARDERROR)(
    NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeBitMask,
    ULONG_PTR* Parameters, ULONG ErrorOption, ULONG* ErrorReturn);

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
    ULONG64 DeviceHandle;

    UNIVERSAL_STRING KernelDll;
    UNIVERSAL_STRING NativeDll;

} INJECT_DATA;



void PrepareInjection(DATA_INFO* DataInfo, void* DetourCode);