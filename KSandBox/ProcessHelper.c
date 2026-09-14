#include "ProcessHelper.h"
#include "SystemHelper.h"
#include "ProcessNotify.h"
#include "ImageNotify.h"
#include  "MemoryPool.h"
#include "MemoryHelper.h"
#include "MemoryList.h"
#include "MemoryLock.h"
#include "InjectHelper.h"
#include "FileHelper.h"
#include "DriverEntry.h"
#include "ImageNotify.h"


//注册进程回调
static BOOLEAN _IsProcessNotifyProcedure = FALSE;

PERESOURCE __ProcessListLock = NULL;



#ifdef USE_PROCESS_MAP
HASH_MAP Process_Map;
HASH_MAP Process_MapDfp;
HASH_MAP Process_MapFcp;
#else
static LIST _ProcessList;    //没有见回收?????????????????????
LIST Process_ListDfp;
LIST Process_ListFcp;
#endif    



BOOLEAN InitializeProcess(void)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;


#ifdef USE_PROCESS_MAP
    map_init(&Process_Map, Driver_Pool);
    map_resize(&Process_Map, 128); // prepare some buckets for better performance

    map_init(&Process_MapDfp, Driver_Pool);
    map_resize(&Process_MapDfp, 128); // prepare some buckets for better performance

    map_init(&Process_MapFcp, Driver_Pool);
    map_resize(&Process_MapFcp, 128); // prepare some buckets for better performance
#else
    InitializeList(&_ProcessList);     
    //List_Init(&Process_ListDfp);
    //List_Init(&Process_ListFcp);
#endif




    if (!GetResourceLock(&__ProcessListLock, TRUE))
        return FALSE;


    //初始化一个事件
    if (!InitializeInjectProcess())
        return FALSE;
    
    




    if (__OsVersion >= WINDOWS_7) {

        Status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyProcedure, FALSE);
    }
#ifdef XP_SUPPORT
    else { // XP, Vista

        Status = PsSetCreateProcessNotifyRoutine(ProcessNotifyProcedure, FALSE);
    }

#ifndef _WIN64

    if ((Status == STATUS_INVALID_PARAMETER) &&
        (__OsVersion < DRIVER_WINDOWS_VISTA)) {

        Status = Process_HookProcessNotify(Process_NotifyProcess);
    }

#endif _WIN64
#endif

    if (NT_SUCCESS(Status)) {

        _IsProcessNotifyProcedure = TRUE;

    }
    else {

        // too many notify routines are already installed in the system
     
        return FALSE;
    }

    //
    // install image notify routines
    //


    
    Status = PsSetLoadImageNotifyRoutine(ImageNotifyProcedure);
    if (NT_SUCCESS(Status))
        __IsImageNotifyProcedure = TRUE;
    else {
      
        return FALSE;
    }
   

    //
    // set syscalls handlers that are applicable in Vista and later
    // Note: NtCreateProcess/NtCreateProcessEx seam not to be used
    //


    /*
    if (!Syscall_Set1("CreateUserProcess", Process_CreateUserProcess))
        return FALSE;
    */

    //
    // set API functions
    //

    /*
    Api_SetFunction(API_START_PROCESS, Process_Api_Start);*/
    SetCommonService(QUERY_PROCESS, QueryProcess);
    SetCommonService(QUERY_PROCESS_INFO,QueryProcessInfo);
    SetCommonService(QUERY_BOX_PATH, QueryBoxPath);     //HookCreateEvent
    /*
 
    
    Api_SetFunction(API_QUERY_PROCESS_PATH, Process_Api_QueryProcessPath);
    Api_SetFunction(API_QUERY_PATH_LIST, Process_Api_QueryPathList);*/
    SetCommonService(ENUM_PROCESSES, EnumProcessEx);

    /*
    Api_SetFunction(API_KILL_PROCESS, Process_Api_Kill);
    */

    return TRUE;
}


void UninitializeProcess(BOOLEAN FreeLock)
{


    if (__IsImageNotifyProcedure) {

        PsRemoveLoadImageNotifyRoutine(ImageNotifyProcedure);
        __IsImageNotifyProcedure = FALSE;
    }

    if (_IsProcessNotifyProcedure) {

        if (__OsVersion >= WINDOWS_7) {

            PsSetCreateProcessNotifyRoutineEx(ProcessNotifyProcedure, TRUE);
        }
#ifdef XP_SUPPORT
        else { // XP, Vista

            PsSetCreateProcessNotifyRoutine(ProcessNotifyProcedure, TRUE);
        }

#ifndef _WIN64

        /*
        if (Process_pOldNotifyProcess) {
            PCREATE_PROCESS_NOTIFY_ROUTINE OldNotifyProcess =
                (PCREATE_PROCESS_NOTIFY_ROUTINE)InterlockedExchange(
                    (volatile LONG*)Process_pOldNotifyProcess, 0);
            if (OldNotifyProcess)
                PsSetCreateProcessNotifyRoutine(OldNotifyProcess, FALSE);
            Process_pOldNotifyProcess = NULL;
        }*/

#endif _WIN64
#endif

        _IsProcessNotifyProcedure = FALSE;

    }
    

    UninitializeInjectProcess();

    if (FreeLock)
        FreeResourceLock(&__ProcessListLock);
}




void GetProcessName(
    POOL* Pool, ULONG_PTR ProcessIdentity,
    void** VirtualAddress, ULONG* ViewSize, WCHAR** BufferData)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientIdentity;
    HANDLE ProcessHandle;
    ULONG v7;

    *VirtualAddress = NULL;
    *ViewSize = 0;
    *BufferData = NULL;

    if (!ProcessIdentity)
        return;

    InitializeObjectAttributes(&ObjectAttributes,
        NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    ClientIdentity.UniqueProcess = (HANDLE)ProcessIdentity;
    ClientIdentity.UniqueThread = 0;

    Status = ZwOpenProcess(
        &ProcessHandle, 0x400, &ObjectAttributes, &ClientIdentity);   //PROCESS_QUERY_INFORMATION

    if (!NT_SUCCESS(Status))
        return;

    Status = ZwQueryInformationProcess(
        ProcessHandle, ProcessImageFileName, NULL, 0, &v7);

    if (Status == STATUS_INFO_LENGTH_MISMATCH) 
    {

        ULONG v8 = v7 + 8 + 8;   //申请的内存大小

        //ushort length
        //ushort maxLength
        //wchar* Buffer  NULL
        //C:\windows\system32\calc.exe
        //
        //


        UNICODE_STRING* v1 = AllocateMemoryEx(Pool,v8,FALSE);
        if (v1) {

            v1->Buffer = NULL;

            Status = ZwQueryInformationProcess(
                ProcessHandle, ProcessImageFileName, v1, v7 + 8, &v7);

            if (NT_SUCCESS(Status) && v1->Buffer) 
            {

                WCHAR* v2;
                v1->Buffer[v1->Length / sizeof(WCHAR)] = L'\0';
                if (!v1->Buffer[0]) 
                {
                    v1->Buffer[0] = L'?';
                    v1->Buffer[1] = L'\0';
                }
                v2 = wcsrchr(v1->Buffer, L'\\');
                if (v2) {
                    ++v2;
                    if (!*v2)
                        v2 = v1->Buffer;
                }
                else
                    v2 = v1->Buffer;
                *VirtualAddress = v1;
                *ViewSize = v8;
                *BufferData = v2;

            }
            else
                FreeMemory(v1, v8);
        }
    }

    ZwClose(ProcessHandle);
}



PROCESS* CreateProcess(
    HANDLE ProcessIdentity, const BOX* Box, const WCHAR* ImagePath,
    KIRQL* Irql)
{
    POOL* Pool;
    PROCESS* Process = NULL;   //自定义结构
    PEPROCESS ProcessObject;
    NTSTATUS Status;
    KIRQL v10;
    BOOLEAN locks_ok;

    //
    // create a pool and initialize a PROCESS block
    //

    Pool = CreateMemoryPool();
    if (!Pool) {
      
        CreateTerminated(ProcessIdentity, Box->SessionIdentity);
        return NULL;
    }

    Process = MemoryPoolAllocate(Pool, sizeof(PROCESS));
    if (!Process) {
        // first allocation from a new pool should never fail

        DeleteMemoryPool(Pool);
        CreateTerminated(ProcessIdentity, Box->SessionIdentity);
        return NULL;
    }

    MemoryZero(Process, sizeof(PROCESS));

    Process->ProcessIdentity = ProcessIdentity;
    Process->Pool = Pool;



    Process->Box = CloneBox(Pool, Box);
    if (!Process->Box) {
        DeleteMemoryPool(Pool);
        CreateTerminated(ProcessIdentity, Box->SessionIdentity);
        return NULL;
    }

    //
    // initialize process creation time and integrity level
    //

    Status = PsLookupProcessByProcessId(Process->ProcessIdentity, &ProcessObject);
    if (!NT_SUCCESS(Status)) {

        

        DeleteMemoryPool(Pool);
        CreateTerminated(ProcessIdentity, Box->SessionIdentity);
        return NULL;
    }

    Process->CreateTime = PsGetProcessCreateTimeQuadPart(ProcessObject);

    ObDereferenceObject(ProcessObject);


    KeRaiseIrql(APC_LEVEL, &v10);
    ExAcquireResourceExclusiveLite(__ProcessListLock, TRUE);

#ifdef USE_PROCESS_MAP
    map_insert(&Process_Map, ProcessId, proc, 0);
#else
    InsertAfter(&_ProcessList, NULL, Process);
#endif

    *Irql = v10;

    return Process;
}
void CreateTerminated(HANDLE ProcessIdentity, ULONG SessionIdentity)
{
    UNICODE_STRING v1;
    PROCESS* Process;
    KIRQL Irql;

    if (SessionIdentity != -1) { // for StartRunAlertDenied, don't log in this case

        v1.Length = 10 * sizeof(WCHAR);
        v1.MaximumLength = v1.Length + sizeof(WCHAR);

        v1.Buffer = MemoryPoolAllocate(__Pool, v1.MaximumLength);
        if (v1.Buffer) {


            //格式化打印
            RtlIntPtrToUnicodeString((ULONG_PTR)ProcessIdentity, 10, &v1);
         

            FreeMemoryEx(v1.Buffer, v1.MaximumLength);
        }
    }

    Process = MemoryPoolAllocate(__Pool, sizeof(PROCESS));
    if (Process) {

        MemoryZero(Process, sizeof(PROCESS));
        Process->ProcessIdentity = ProcessIdentity;
        Process->Pool = __Pool;
        SetTerminated(Process, 1);

        KeRaiseIrql(APC_LEVEL, &Irql); 
        ExAcquireResourceExclusiveLite(__ProcessListLock, TRUE);

#ifdef USE_PROCESS_MAP

#else
        InsertAfter(&_ProcessList, NULL, Process);
#endif

        ExReleaseResourceLite(__ProcessListLock);
        KeLowerIrql(Irql);
    }
}
void SetTerminated(PROCESS* Process, ULONG Reason)
{
    //
    // This function marks a process for termination, this causes File_PreOperation 
    // and Key_Callback to return STATUS_PROCESS_IS_TERMINATING which prevents 
    // the process form accessing the file system and the registry
    // 
    // Note: if this is set during process creation the process won't be able to start at all
    //

    if (!Process->IsTerminated)
    {
        Process->IsTerminated = TRUE;
        Process->Reason = Reason;
    }
}
PROCESS* FindProcess(HANDLE ProcessIdentity, KIRQL* Irql)
{
    PROCESS* Process;
    KIRQL v10;
    BOOLEAN IsTerminated;

    //
    // if we're looking for the current process, then check execution mode
    // to make sure it isn't a system process or kernel mode caller
    //

    if (!ProcessIdentity) {

        if (ExGetPreviousMode() == KernelMode)
            ProcessIdentity = (HANDLE)0;
        else
            ProcessIdentity = PsGetCurrentProcessId();

        if (ProcessIdentity < (HANDLE)8) {

            if (Irql) {
                // in case caller expects a locked process list on return
                KeRaiseIrql(APC_LEVEL, Irql);
                ExAcquireResourceSharedLite(__ProcessListLock, TRUE);
            }

            return NULL;
        }

        IsTerminated = TRUE;

    }
    else
        IsTerminated = FALSE;

    //
    // find a PROCESS block that matches the current ProcessId
    //

    KeRaiseIrql(APC_LEVEL, &v10);
    ExAcquireResourceSharedLite(__ProcessListLock, TRUE);

#ifdef USE_PROCESS_MAP
    Process = map_get(&Process_Map, ProcessId);
    if (Process) {
#else
    Process = GetListHead(&_ProcessList);
    while (Process) {
        if (Process->ProcessIdentity == ProcessIdentity) {
#endif

            if (IsTerminated && Process->IsTerminated) 
            {
              
            }

#ifndef USE_PROCESS_MAP
            break;
        }

        Process = GetNextNode(Process);
#endif
    }

    if (Irql) {

        *Irql = v10;

    }
    else {

        ExReleaseResourceLite(__ProcessListLock);
        KeLowerIrql(v10);
    }

    return Process;
    
}

void DeleteProcess(HANDLE ProcessIdentity)
{
    PROCESS* Process;
    KIRQL Irql;

    //
    // find the sandboxed process with the specified process id
    //

    Process = NULL;

    KeRaiseIrql(APC_LEVEL, &Irql);
    ExAcquireResourceExclusiveLite(__ProcessListLock, TRUE);

#ifdef USE_PROCESS_MAP
    map_take(&Process_Map, ProcessId, &proc, 0);
#else
    Process = GetListHead(&_ProcessList);
    while (Process) 
    {
        if (Process->ProcessIdentity == ProcessIdentity)
        {
            RemoveCurrent(&_ProcessList, Process);
            break;
        }
        Process = (PROCESS*)GetNextNode(Process);
    }
#endif

    //Process_DfpDelete(ProcessId);

    //Process_FcpDelete(ProcessId);

    ExReleaseResourceLite(__ProcessListLock);
    KeLowerIrql(Irql);

    if (Process) 
    {

        if (Process->Pool == __Pool)
            FreeMemoryEx(Process, sizeof(PROCESS));

        else {

            //
            // process was found to be sandboxed:  it was already unlinked
            // from Process_List.  we have to do some process clean-up
            //

            /*
            WFP_DeleteProcess(proc);
            Key_UnmountHive(proc);
            if (proc->file_lock)
                Mem_FreeLockResource(&proc->file_lock);
            if (proc->key_lock)
                Mem_FreeLockResource(&proc->key_lock);
            if (proc->ipc_lock)
                Mem_FreeLockResource(&proc->ipc_lock);
            if (proc->gui_lock)
                Mem_FreeLockResource(&proc->gui_lock);

            Token_ResetPrimary(proc);

            Thread_ReleaseProcess(proc);

            Token_ReleaseProcess(proc);

            Pool_Delete(proc->pool);

            */
        }
    }
}
NTSTATUS EnumerateProcess(
    const WCHAR* BoxName, BOOLEAN IsAllSessions, ULONG SessionIdentity,
    ULONG* ProcessIdentitys, ULONG* Count)
{
    NTSTATUS Status;
    PROCESS* Process;
    ULONG num;
    KIRQL Irql;

    if (Count == NULL)
        return STATUS_INVALID_PARAMETER;

    //
    // return only processes of the caller user in their logon session
    //

    if ((!IsAllSessions) && (SessionIdentity == -1))
    {

        Status = GetSessionIdentity(&SessionIdentity);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    KeRaiseIrql(APC_LEVEL, &Irql);
    ExAcquireResourceSharedLite(__ProcessListLock, TRUE);

    __try {


        *Count = 1;
        Status = STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }
   
    ExReleaseResourceLite(__ProcessListLock);
    KeLowerIrql(Irql);

    return Status;
}


NTSTATUS GetSessionIdentity(ULONG* SessionIdentity)
{
    NTSTATUS Status;
    PROCESS_SESSION_INFORMATION ProcessSessionInfo;
    ULONG v7;

    v7 = sizeof(ProcessSessionInfo);
    Status = ZwQueryInformationProcess(
        NtCurrentProcess(), ProcessSessionInformation,
        &ProcessSessionInfo, sizeof(ProcessSessionInfo), &v7);

    if (NT_SUCCESS(Status))
        *SessionIdentity = ProcessSessionInfo.SessionId;
    else
        *SessionIdentity = 0;

    return Status;
}


PEPROCESS GetProcessObject(
    HANDLE ProcessIdentity, UNICODE_STRING* SidString, ULONG* SessionIdentity)
{
    PEPROCESS ProcessObject;
    PACCESS_TOKEN TokenObject;

    NTSTATUS Status = PsLookupProcessByProcessId(ProcessIdentity, &ProcessObject);
    if (!NT_SUCCESS(Status)) {

        ProcessObject = NULL;
        *SessionIdentity = -1;

    }
    else {

        *SessionIdentity = PsGetProcessSessionId(ProcessObject);

        if (SidString) {

            TokenObject = PsReferencePrimaryToken(ProcessObject);
            Status = QuerySidString(TokenObject, SidString);
            PsDereferencePrimaryToken(TokenObject);

            if (!NT_SUCCESS(Status)) {

                ObDereferenceObject(ProcessObject);
                ProcessObject = NULL;
            }
        }
    }

    return ProcessObject;
}


NTSTATUS QuerySidString(
    void* TokenObject, UNICODE_STRING* SidString)
{
    TOKEN_USER* TokenUserData = NULL;
    NTSTATUS status = SeQueryInformationToken(
        TokenObject, TokenUser, &TokenUserData);
    if (NT_SUCCESS(status)) {

        status = RtlConvertSidToUnicodeString(
            SidString, TokenUserData->User.Sid, TRUE);

        ExFreePool(TokenUserData);
    }

    return status;
}
BOOLEAN IsProcessRunningAsSystemAccount(HANDLE ProcessIdenity)
{
    UNICODE_STRING SidString;
    ULONG SessionIdentity;
    BOOLEAN IsSystem;

    NTSTATUS Status = GetSidStringAndSessionIdentity(
        NULL, ProcessIdenity, &SidString, &SessionIdentity);

    if (NT_SUCCESS(Status)) {

        


        IsSystem = (_wcsicmp(SidString.Buffer, __S_1_5_18) == 0 ||
            _wcsicmp(SidString.Buffer, __S_1_5_19) == 0 ||
            _wcsicmp(SidString.Buffer, __S_1_5_20) == 0);

        RtlFreeUnicodeString(&SidString);

    }
    else
        IsSystem = FALSE;

    return IsSystem;
}

NTSTATUS GetSidStringAndSessionIdentity(
    HANDLE ProcessHandle, HANDLE ProcessIdentity,
    UNICODE_STRING* SidString, ULONG* SessionIdentity)
{
    NTSTATUS Status;
    PEPROCESS ProcessObject = NULL;
    PACCESS_TOKEN TokenObject;

    if (ProcessHandle == NtCurrentProcess()) {

        ProcessObject = PsGetCurrentProcess();
        ObReferenceObject(ProcessObject);
        Status = STATUS_SUCCESS;

    }
    else if (ProcessHandle) {

        const KPROCESSOR_MODE AccessMode =
            ((ProcessHandle == NtCurrentProcess()) ? KernelMode : UserMode);

        Status = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType,
            AccessMode, &ProcessObject, NULL);

    }
    else if (ProcessIdentity) {

        Status = PsLookupProcessByProcessId(ProcessHandle, &ProcessObject);

    }
    else {

        Status = STATUS_INVALID_PARAMETER;
    }

    if (NT_SUCCESS(Status)) {

        *SessionIdentity = PsGetProcessSessionId(ProcessObject);

        TokenObject = PsReferencePrimaryToken(ProcessObject);
        Status = QuerySidString(TokenObject, SidString);
        PsDereferencePrimaryToken(TokenObject);

        ObDereferenceObject(ProcessObject);
    }

    if (!NT_SUCCESS(Status)) {

        SidString->Buffer = NULL;
        *SessionIdentity = -1;
    }

    return Status;
}

void GetCurrentDirectory(
    PEPROCESS ProcessObject, WCHAR** CurrentDirectory, ULONG* DirectoryLength)
{
    WCHAR* v5;
    ULONG v7;

    const ULONG Offset =
#ifdef _WIN64
        0x38;   // 64-bit
#else
        0x24;   // 32-bit
#endif

    * CurrentDirectory = NULL;
    *DirectoryLength = 0;

    GetStringFromPeb(
        ProcessObject, Offset, 600, &v5, &v7);
    if (v5 && v7) {

        //
        // buffer was allocated with some extra space
        //

        NTSTATUS Status;
        WCHAR* v1 = v5 + wcslen(v5);

        /*
        kd> db fffff8a0`016fb900
fffff8a0`016fb900  43 00 3a 00 5c 00 50 00-72 00 6f 00 67 00 72 00  C.:.\.P.r.o.g.r.
fffff8a0`016fb910  61 00 6d 00 20 00 46 00-69 00 6c 00 65 00 73 00  a.m. .F.i.l.e.s.
fffff8a0`016fb920  20 00 28 00 78 00 38 00-36 00 29 00 5c 00 57 00   .(.x.8.6.).\.W.
fffff8a0`016fb930  69 00 6e 00 64 00 6f 00-77 00 73 00 20 00 4b 00  i.n.d.o.w.s. .K.
fffff8a0`016fb940  69 00 74 00 73 00 5c 00-31 00 30 00 5c 00 44 00  i.t.s.\.1.0.\.D.
fffff8a0`016fb950  65 00 62 00 75 00 67 00-67 00 65 00 72 00 73 00  e.b.u.g.g.e.r.s.
fffff8a0`016fb960  5c 00 00 00 75 52 48 66-4f 30 71 73 50 62 7a 54  \.
        */


        while (v1 > v5 && v1[-1] == L'\\')
            --v1;
        if (v1 > v5) {

            v1[0] = L'\\';
            v1[1] = L'x';
            v1[2] = L'\0';

            //
            // get canonical path
            //

            Status = TranslateDosToNt(
                v5, CurrentDirectory, DirectoryLength);
            if (!NT_SUCCESS(Status)) {

                *CurrentDirectory = NULL;
                *DirectoryLength = 0;
            }
        }

        FreeMemoryEx(v5, v7);
    }
}

void GetStringFromPeb(
    PEPROCESS ProcessObject, ULONG Offset, ULONG MaxLength,
    WCHAR** OutBuffer, ULONG* OutLength)
{
    ULONG_PTR Peb;
    ULONG_PTR RtlUserProcessParameters;
    UNICODE_STRING* v1;
    WCHAR* v5, * Buffer;
    ULONG v7, Length, MaximumLength;
    KAPC_STATE ApcState;

    *OutBuffer = NULL;
    *OutLength = 0;

    Peb = PsGetProcessPeb(ProcessObject);
    if (!Peb)
        return;

    v7 = (MaxLength + 16) * sizeof(WCHAR);
    v5 = MemoryPoolAllocate(__Pool, v7);
    if (!v5)
        return;

    KeStackAttachProcess(ProcessObject, &ApcState);   //切换进程上下背景文

    __try {

        //
        // make sure PEB block is accessible
        //
        //Peb中获取参数块
        const ULONG Offset1 =
#ifdef _WIN64
            0x20;   // 64-bit
#else
            0x10;   // 32-bit
#endif

        ProbeForRead((void*)Peb, 0x20, sizeof(ULONG_PTR));
        RtlUserProcessParameters = *(ULONG_PTR*)(Peb + Offset1);
        ProbeForRead((void*)RtlUserProcessParameters, 0x50, sizeof(ULONG_PTR));

        //
        // make sure the requested string is accessible
        //

        v1 = (UNICODE_STRING*)(RtlUserProcessParameters + Offset);
        ProbeForRead(v1, sizeof(UNICODE_STRING), sizeof(ULONG));

        Length = v1->Length / sizeof(WCHAR);
        MaximumLength = v1->MaximumLength / sizeof(WCHAR);
        Buffer = v1->Buffer;

        if (Length && MaximumLength && Buffer &&
            Length <= MaxLength && Length <= MaximumLength) {

            if ((ULONG_PTR)Buffer < (ULONG_PTR)RtlUserProcessParameters) {
                Buffer = (WCHAR*)
                    ((ULONG_PTR)RtlUserProcessParameters + (ULONG_PTR)Buffer);
            }

            ProbeForRead(Buffer, Length * sizeof(WCHAR), sizeof(WCHAR));

            //
            // success
            //

            wmemcpy(v5, Buffer, Length);
            v5[Length] = L'\0';

            *OutBuffer = v5;
            *OutLength = v7;
            v5 = NULL;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    KeUnstackDetachProcess(&ApcState);

    //
    // free when not used
    //

    if (v5)
        FreeMemoryEx(v5, v7);
}


void GetDocArgument(
    PEPROCESS ProcessObject, WCHAR** DocArgument, ULONG* ArgumentLength)
{
    WCHAR* v5;
    ULONG v7;

    const ULONG Offset =
#ifdef _WIN64
        0x70;   // 64-bit
#else
        0x40;   // 32-bit
#endif

    * DocArgument = NULL;
    *ArgumentLength = 0;

    GetStringFromPeb(
        ProcessObject, Offset, 600, &v5, &v7);
    if (v5 && v7) {

        //
        // eat first command line argument, the image name
        //

        ULONG Length = wcslen(v5);
        WCHAR* v1 = v5;
        //0xfffff8a0`016fbb10 "C:\Windows\notepad.exe"
     

        while (Length && *v1 == L' ') {
            --Length;
            ++v1;
        }

        if (Length) {

            if (*v1 == L'\"') {

                --Length;
                ++v1;
                while (Length && *v1 != L'\"') {
                    --Length;
                    ++v1;
                }
                if (Length) {
                    --Length;
                    ++v1;
                }

            }
            else {

                while (Length && *v1 != L' ') {
                    --Length;
                    ++v1;
                }
            }
        }

        //
        // eat optional arguments
        //

        while (Length) {

            while (Length && *v1 == L' ') {
                --Length;
                ++v1;
            }

            if (*v1 != L'-' && *v1 != L'/')
                break;

            while (Length && *v1 != L' ') {
                --Length;
                ++v1;
            }
        }

        //
        // eat second command line argument, the document path
        //

        if (Length) {

            WCHAR* v10;

            // Remove any leading spaces or quotes
            while (Length && (*v1 == L' ' || *v1 == L'"')) {
                --Length;
                ++v1;
            }


            // Now strip any trailing backslashes, quotes or spaces
            while (Length && (v1[Length - 1] == L'\\' || v1[Length - 1] == L' ' || v1[Length - 1] == L'"')) {
                --Length;
                v1[Length] = 0;
            }

            v10 = v1;
            // DbgPrint("After Doc Trim: [%S]\n", doc);

            //
            // now that we've stripped any quotes, leading spaces
            // and suffix backslashes, get a canonical path
            //

            if (*v10) {

                NTSTATUS Status = TranslateDosToNt(v10, DocArgument, ArgumentLength);
                if (!NT_SUCCESS(Status)) {

                    *DocArgument = NULL;
                    *ArgumentLength = 0;
                }
            }
        }

        FreeMemoryEx(v5, v7);
    }
}