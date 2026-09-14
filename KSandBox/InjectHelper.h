#pragma once
#include "Common.h"
#include "ProcessHelper.h"
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

}PROCESS_MESSAGE,*PPROCESS_MESSAGE;


BOOLEAN InitializeInjectProcess(void);
void UninitializeInjectProcess(void);

BOOLEAN InjectProcessRequest(
    HANDLE ProcessIdentity, ULONG SessionIdentity, ULONG64 CreateTime,
    const WCHAR* ImageName, BOOLEAN add_process_to_job, BOOLEAN IsHostInject);


NTSTATUS InjectProcessComplete(PROCESS* Process, ULONG64* ParameterData);
