#include "Common.h"
#include "Syscall.h"
#include "MemoryList.h"
#include "PeHelper.h"
#include "MemoryPool.h"


LIST __SyscallsList;    //没有卸载内存   Ssdt
UCHAR* __SyscallsCode = NULL;   //没有卸载内存 Ssdt Exports   

static SYSCALL_ENTRY* __SetInformationThread = NULL;


static ULONG _MaxIndex = 0;




BOOLEAN GetSystemServiceInfo(void)
{
    BOOLEAN IsOk = FALSE;
    PDLL_ENTRY Ntdll;

    UCHAR* ServiceName;
    ULONG ServiceIndex, ServiceOffset;
    ULONG v1 = 0;
    ULONG NameLength = 0;
    UCHAR* ServiceAddress1 = NULL;    //获取服务的索引
    void* ServiceAddress2 = NULL;
    ULONG ParameterCount;
    SYSCALL_ENTRY* SyscallEntry = NULL;
    ULONG v7 = 0;
    InitializeList(&__SyscallsList);

    //
    // prepare the approve and disabled lists
    //

    /*
    LIST disabled_hooks;
    Syscall_LoadHookMap(L"DisableWinNtHook", &disabled_hooks);

    LIST approved_syscalls;
    Syscall_LoadHookMap(L"ApproveWinNtSysCall", &approved_syscalls);
    */
    //
    // scan each ZwXxx export in NTDLL
    //

    Ntdll = LoadDll(__Ntdll);   //重载Ntdll   
    if (!Ntdll)
        goto Exit;


    ServiceOffset = GetProcAddress(Ntdll, "Zw", &ServiceName, &v1);
    if (!ServiceOffset)
        goto Exit;

    while (ServiceOffset) {

        if (ServiceName[0] != 'Z' || ServiceName[1] != 'w')
            break;
        ServiceName += 2;                  // skip Zw prefix
        for (NameLength = 0; (NameLength < 64) && ServiceName[NameLength]; ++NameLength)
            ;

        //DbgPrint("    Found SysCall %s\n", name);

        //entry = NULL;

        //
        // we don't hook ZwXxx services which do not or may not return to
        // caller. this is because the invocation of Syscall_Api_Invoke
        // goes through IopXxxControlFile (called by NtDeviceIoControlFile)
        // which takes a reference on the file object for our API device
        // object, and no return means there is no corresponding dereference
        // for the file object.  there could be other nasty side effects.
        //
        // ZwXxx services:   ZwContinue, ZwCallbackReturn, ZwRaiseException,
        // NtTerminateJobObject, NtTerminateProcess, NtTerminateThread
        //

#define IS_PROCEDURE_NAME(Length,Name) (NameLength == Length && memcmp(ServiceName, Name, Length) == 0)

        if (IS_PROCEDURE_NAME(8, "Continue")
            || IS_PROCEDURE_NAME(10, "ContinueEx")
            || IS_PROCEDURE_NAME(14, "CallbackReturn")
            || IS_PROCEDURE_NAME(14, "RaiseException")
            || IS_PROCEDURE_NAME(18, "TerminateJobObject")
            || IS_PROCEDURE_NAME(16, "TerminateProcess")
            || IS_PROCEDURE_NAME(15, "TerminateThread")

            ) {
            goto Next;
        }

        //
        // on 64-bit Windows, some syscalls are fake, and should be skipped
        //

        if (IS_PROCEDURE_NAME(15, "QuerySystemTime"))
            goto Next;


        // ICD-10607 - McAfee uses it to pass its own data in the stack. The call is not important to us. 
        //if (    IS_PROC_NAME(14, "YieldExecution")) // $Workaround$ - 3rd party fix
        //    goto next_zwxxx;

        //
        // the Google Chrome "wow_helper" process expects NtMapViewOfSection
        // to not be already hooked.  although this is needed only on 64-bit
        // Vista, this particular syscall is not very important to us, so
        // for sake of consistency, we skip hooking it on all platforms
        //
        //if (    IS_PROC_NAME(16,  "MapViewOfSection")) // $Workaround$ - 3rd party fix
        //    goto next_zwxxx;

        //if (Syscall_HookMapMatch(name, name_len, &disabled_hooks))
        //    goto next_zwxxx;

#undef IS_PROCEDURE_NAME

        //
        // analyze each ZwXxx export to find the service index number
        //



        ServiceAddress1 = RvaToFoa(Ntdll, ServiceOffset);    //获取服务索引
        if (ServiceAddress1)
        {
            ServiceIndex = GetSystemServiceIndex(ServiceAddress1);   //    ssdt  mov

            /*
            kd> u 00000000002d0ce0
            00000000`002d0ce0 4c8bd1          mov     r10,rcx
            00000000`002d0ce3 b860000000      mov     eax,60h
            00000000`002d0ce8 0f05            syscall
            00000000`002d0cea c3              ret


            */
            if (ServiceIndex == -2) {
                //
                // if ZwXxx export is not a real syscall, then skip it
                //
                goto Next;
            }
            if (ServiceIndex != -1) {
                GetSystemServiceAddress(
                    ServiceIndex, &ServiceAddress2, &ParameterCount);

                //DbgPrint("    Found SysCall: %s, pcnt %d; idx: %d\r\n", name, param_count, syscall_index);
            }


            if (!ServiceAddress2)
            {


                goto Exit;
            }
            v7 = sizeof(SYSCALL_ENTRY) + NameLength + 1;
            SyscallEntry = AllocateMemoryEx(__Pool, v7, TRUE);
            if (!SyscallEntry)
                goto Exit;

            SyscallEntry->ServiceIndex = (USHORT)ServiceIndex;
            SyscallEntry->ParameterCount = (USHORT)ParameterCount;
            SyscallEntry->ServiceOffset = ServiceOffset;
            SyscallEntry->ServiceAddress = ServiceAddress2;
            SyscallEntry->SyscallHandler1 = NULL;
            SyscallEntry->SyscallHandler2 = NULL;

#ifdef _M_AMD64
            SyscallEntry->SyscallHandler3 = NULL;
#endif

            SyscallEntry->NameLength = (USHORT)NameLength;
            memcpy(SyscallEntry->ServiceName, ServiceName, NameLength);
            SyscallEntry->ServiceName[NameLength] = '\0';

            InsertAfter(&__SyscallsList, NULL, SyscallEntry);

            if (ServiceIndex > _MaxIndex)
                _MaxIndex = ServiceIndex;
        }
    Next:

        ServiceOffset = GetProcAddress(Ntdll, NULL, &ServiceName, &v1);
    }

    IsOk = TRUE;


    if (_MaxIndex < 100) {
      
        IsOk = FALSE;
    }

    if (_MaxIndex >= 500) {
       
        IsOk = FALSE;
    }
    if (!IsOk)
        _MaxIndex = 0;
Exit:
    return IsOk;
}
BOOLEAN GetSystemServiceCode(void)
{
    UCHAR* Exports[] = NATIVE_FUNCTION_NAMES;   //Ntdll导出函数
    SYSCALL_ENTRY* SyscallEntry;
    DLL_ENTRY* Ntdll;
    UCHAR* ServiceAddress;
    ULONG i;

    //
    // allocate some space to save code from ntdll
    //

    __SyscallsCode = AllocateMemoryEx(__Pool, (NATIVE_FUNCTION_SIZE * NATIVE_FUNCTION_COUNT), TRUE);
    if (!__SyscallsCode)
        return FALSE;

    Ntdll = LoadDll(__Ntdll);
    if (!Ntdll)
        return FALSE;

    //
    // save a copy of some syscall functions in ntdll, we will pass
    // these to SbieSvc, which in turn will pass them to SbieLow
    // (see core/svc/DriverAssistInject.cpp and core/low/lowdata.h)
    //

    for (i = 0; i < NATIVE_FUNCTION_COUNT; ++i) {

        SyscallEntry = GetSyscallEntry(Exports[i] + 2); // +2 skip Nt prefix
        if (!SyscallEntry)
            return FALSE;

        ServiceAddress = RvaToFoa(Ntdll, SyscallEntry->ServiceOffset);
        if (!ServiceAddress) {
      
            return FALSE;
        }

        memcpy(__SyscallsCode + (i * NATIVE_FUNCTION_SIZE), ServiceAddress, NATIVE_FUNCTION_SIZE);
    }

    //
    // get the syscall for NtSetInformationThread (see Syscall_Api_Invoke)
    //

    __SetInformationThread = GetSyscallEntry("SetInformationThread");

    //
    // finish
    //

    return TRUE;
}
SYSCALL_ENTRY* GetSyscallEntry(const UCHAR* ServiceName)
{
    ULONG NameLength = strlen(ServiceName);

    SYSCALL_ENTRY* SyscallEntry = GetListHead(&__SyscallsList);
    while (SyscallEntry) {

        if (SyscallEntry->NameLength == NameLength
            && memcmp(SyscallEntry->ServiceName, ServiceName, NameLength) == 0) {

            return SyscallEntry;
        }

        SyscallEntry = GetNextNode(SyscallEntry);
    }

    return NULL;
}

