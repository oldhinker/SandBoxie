#pragma once
#include "Common.h"
#include "ObjectHelper.h"

typedef
NTSTATUS(__stdcall* LPFN_NTOPENFILE)(
    OUT PHANDLE                     FileHandle,
    IN ACCESS_MASK                  DesiredAccess,
    IN POBJECT_ATTRIBUTES           ObjectAttributes,
    OUT PIO_STATUS_BLOCK            IoStatusBlock,
    IN ULONG                        ShareAccess,
    IN ULONG                        OpenOptions);

typedef
NTSTATUS(__stdcall* LPFN_NTCLOSE)(
    IN HANDLE                       FileHandle
    );
typedef
NTSTATUS(__stdcall* LPFN_NTDEVICEIOCONTROLFILE)(
    IN HANDLE                       FileHandle,
    IN HANDLE                       Event  OPTIONAL,
    IN PVOID                        ApcRoutine  OPTIONAL,
    IN PVOID                        ApcContext  OPTIONAL,
    OUT PIO_STATUS_BLOCK            IoStatusBlock,
    IN ULONG                        IoControlCode,
    IN PVOID                        InputBuffer OPTIONAL,
    IN ULONG                        InputBufferLength,
    OUT PVOID                       OutputBuffer OPTIONAL,
    IN ULONG                        OutputBufferLength
    );

BOOLEAN InitializeFile(void);


extern LPFN_NTOPENFILE __NtOpenFile;
extern LPFN_NTCLOSE __NtClose;
extern LPFN_NTDEVICEIOCONTROLFILE __NtDeviceIoControlFile;