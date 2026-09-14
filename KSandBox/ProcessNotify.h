#pragma once
#include "Common.h"
#include "ProcessHelper.h"


#ifdef XP_SUPPORT
#ifndef _WIN64

static NTSTATUS Process_HookProcessNotify(
    PCREATE_PROCESS_NOTIFY_ROUTINE NewNotifyRoutine);

#endif _WIN64

void ProcessNotifyProcedure(
    HANDLE Process, HANDLE ProcessIdentity, BOOLEAN Create);
#endif

void ProcessNotifyProcedure(
    PEPROCESS Process, HANDLE ProcessIdentity, PPS_CREATE_NOTIFY_INFO CreateInfo);

BOOLEAN ProcessNotifyProcedureCreate(
    HANDLE ProcessIdentity, HANDLE ParentProcessIdentity, HANDLE CallerIdentity, VOID* Box);

void ProcessNotifyProcedureDelete(HANDLE ProcessIdentity);

NTSTATUS StartProcessNotify(PROCESS* Process, ULONG64* ParameterData);