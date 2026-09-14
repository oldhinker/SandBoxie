#pragma once
#include "Common.h"
#include "StatusHelper.h"





typedef
VOID
(*PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );


typedef NTSTATUS(*LPFN_NTDEVICEIOCONTROLFILE)(
    IN  HANDLE FileHandle,
    IN  HANDLE Event OPTIONAL,
    IN  PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN  PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN  ULONG IoControlCode,
    IN  PVOID InputBuffer OPTIONAL,
    IN  ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN  ULONG OutputBufferLength);

#define IO_CTL_CODE_1 \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)


LONG IoctlRequest(ULONG64* ParameterData);