#include "InjectHelper.h"
#include "ProcessHelper.h"
#include "IoRequest.h"
#include "DriverEntry.h"
#include "ApiHelper.h"




static KEVENT* _ProcessEvent = NULL;

BOOLEAN InitializeInjectProcess(void)
{
    _ProcessEvent = ExAllocatePoolWithTag(NonPagedPool, sizeof(KEVENT), TAG);
    if (!_ProcessEvent) {
       
        return FALSE;
    }
    KeInitializeEvent(_ProcessEvent, SynchronizationEvent, FALSE);

    SetCommonService(INJECT_COMPLETE, InjectProcessComplete);

    return TRUE;
}
void UninitializeInjectProcess(void)
{
    if (_ProcessEvent) {
        ExFreePoolWithTag(_ProcessEvent, TAG);
        _ProcessEvent = NULL;
    }
}
BOOLEAN InjectProcessRequest(
    HANDLE ProcessIdentity, ULONG SessionIdentity, ULONG64 CreateTime,
    const WCHAR* ImageName, BOOLEAN add_process_to_job, BOOLEAN IsHostInject)
{
   
    PROCESS_MESSAGE ProcessContext;
    ULONG_PTR IsWow64 = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN IsDone = FALSE;
    KIRQL Irql;
    PROCESS* Process;
    //
    // query wow64 flag for new process
    //

#ifdef _WIN64

    if (1) {

        OBJECT_ATTRIBUTES ObjectAttributes;
        CLIENT_ID ClientIdentity;
        HANDLE ProcessHandle;
        ULONG ReturnLength;

        InitializeObjectAttributes(&ObjectAttributes,
            NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        ClientIdentity.UniqueThread = NULL;
        ClientIdentity.UniqueProcess = ProcessIdentity;

        Status = ZwOpenProcess(&ProcessHandle, 0x400,            //PROCESS_QUERY_INFORMATION,
            &ObjectAttributes, &ClientIdentity);

        if (NT_SUCCESS(Status)) {

            //查询启动进程的位数
            Status = ZwQueryInformationProcess(
                ProcessHandle, ProcessWow64Information,
                &IsWow64, sizeof(IsWow64), &ReturnLength);

            ZwClose(ProcessHandle);
        }
    }
#endif _WIN64
    //
    // send message to SbieSvc DriverAssist
    //
    if (NT_SUCCESS(Status)) {

        ULONG Length = wcslen(ImageName);
        const ULONG MaxLength = sizeof(ProcessContext.ImageName) / sizeof(WCHAR) - 1;
        if (Length > MaxLength)
            Length = MaxLength;
        wmemcpy(ProcessContext.ImageName, ImageName, Length);
        ProcessContext.ImageName[Length] = L'\0';

        ProcessContext.ProcessIdentity = (ULONG)(ULONG_PTR)ProcessIdentity;
        ProcessContext.SessionIdentity = SessionIdentity;
        ProcessContext.CreateTime = CreateTime;
        ProcessContext.IsWow64 = (IsWow64 ? TRUE : FALSE);
        ProcessContext.add_to_job = add_process_to_job;
        ProcessContext.IsHostInject = IsHostInject;


        
        //将该信息通过PortObject返回Ring3
        if (!SendLpcMessage(INJECT_PROCESS, sizeof(ProcessContext), &ProcessContext))
            Status = STATUS_SERVER_DISABLED;


        if (NT_SUCCESS(Status)) 
        {

            LARGE_INTEGER Time;
            ULONG i = 0;

            while ((i < 400 * 3) && (!__IsDriverUnloading))
            {

                Process = FindProcess(ProcessIdentity, &Irql);

                if (Process && Process->CreateTime == CreateTime)
                {

               
                    IsDone = Process->IsLowLevelLoaded || Process->IsTerminated;

                    if (!IsWow64)
                    {
                        //proc->ntdll32_base = -1;
                    }
                        
                }

                ExReleaseResourceLite(__ProcessListLock);
                KeLowerIrql(Irql);

                if (IsDone)
                    break;

                Time.QuadPart = -(SECONDS(1) / 4); // 250ms*40 = 10s
                KeWaitForSingleObject(_ProcessEvent,
                    Executive, KernelMode, FALSE, &Time);
                ++i;
            }

            if (!IsDone)           // if no response from SbieSvc
                Status = STATUS_TIMEOUT;
        }

        if (!NT_SUCCESS(Status) && !IsHostInject) {


            /*
            proc = Process_Find(process_id, &irql);

            if (proc && proc->create_time == create_time) {

                Process_SetTerminated(proc, 3);
            }

            ExReleaseResourceLite(Process_ListLock);
            KeLowerIrql(irql);

            */

            return FALSE;
        }

   
    }
    return TRUE; 
}


NTSTATUS InjectProcessComplete(PROCESS* Process, ULONG64* ParameterData)
{
    NTSTATUS Status;

    //
    // this API must be invoked by the Sandboxie service
    //

    if (Process || (PsGetCurrentProcessId() != __ProcessIdentity)) {

        Status = STATUS_ACCESS_DENIED;

    }
    else {

        //
        // turn on the SbieLow loaded flag for the process
        //

        HANDLE ProcessIdentity = (HANDLE)(ULONG_PTR)(ULONG)ParameterData[1];

        KIRQL Irql;
        PROCESS* Process = FindProcess(ProcessIdentity, &Irql);

        if (Process) {

            ULONG IsOk = (ULONG)ParameterData[3];
            if (IsOk)
            {
                //Process_SetTerminated(Process, 3);
            }  
            else
                Process->IsLowLevelLoaded = TRUE;

            //
            // the service dynamically allocates a per box SID to be used,
            // if no SID is provided this feature is either disabled or failed
            // then we fall back to using the default anonymous SID
            //

            __try {

                PSID v1 = (PSID)(ULONG_PTR)ParameterData[2];

                if (v1) {

                    ProbeForRead(v1, SECURITY_MAX_SID_SIZE, sizeof(UCHAR));

                    ULONG Length = RtlLengthSid(v1);
                    //proc->SandboxieLogonSid = Mem_Alloc(proc->pool, sid_length);
                    //memcpy(proc->SandboxieLogonSid, pSID, sid_length);
                }

            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                Status = GetExceptionCode();
            }
        }

        ExReleaseResourceLite(__ProcessListLock);
        KeLowerIrql(Irql);

        if (Process) {

            KeSetEvent(_ProcessEvent, 0, FALSE);
            Status = STATUS_SUCCESS;

        }
        else
            Status = STATUS_INVALID_CID;
    }

    return Status;
}