#include "ProcessNotify.h"
#include "MemoryPool.h"
#include "ProcessHelper.h"
#include "DriverEntry.h"
#include "InjectHelper.h"
#include "MemoryHelper.h"
#include "ApiHelper.h"
#include "ProcessForce.h"


void ProcessNotifyProcedure(
    PEPROCESS Process, HANDLE ProcessIdentity, PPS_CREATE_NOTIFY_INFO CreateInfo)
{

    HANDLE v1 = 0;
    /*
    kd> dq ParentProcess
fffff880`0308edc0  fffffa80`615c1b30

    kd> dt _eprocess fffffa80`615c1b30
 +0x2e0 ImageFileName    : [15]  "calc.exe"


 kd> !process 0 0
    PROCESS fffffa80615c1b30
    SessionId: 1  Cid: 0bc8    Peb: 7fffffdf000  ParentCid: 0690
    DirBase: 117cb0000  ObjectTable: fffff8a0044435c0  HandleCount:   0.
    Image: calc.exe



    kd> dt _PS_CREATE_NOTIFY_INFO fffff880`0308ee40
KSandBox!_PS_CREATE_NOTIFY_INFO
   +0x000 Size             : 0x48
   +0x008 Flags            : 1
   +0x008 FileOpenNameAvailable : 0y1
   +0x008 IsSubsystemProcess : 0y0
   +0x008 Reserved         : 0y000000000000000000000000000000 (0)
   +0x010 ParentProcessId  : 0x00000000`00000690 Void
   +0x018 CreatingThreadId : _CLIENT_ID
   +0x028 FileObject       : 0xfffffa80`61419ce0 _FILE_OBJECT
   +0x030 ImageFileName    : 0xfffff880`0308f680 _UNICODE_STRING "\??\C:\Windows\system32\calc.exe"
   +0x038 CommandLine      : 0xfffffa80`615d9070 _UNICODE_STRING ""C:\Windows\system32\calc.exe" "
   +0x040 CreationStatus   : 0n0

    */



    //
    // don't do anything before the main driver init says it's ok
    //


    if (!__ReadyToSandbox)
        return;

    //
    // handle process creation and deletion.  note that we are running
    // in an arbitrary thread context
    //

    if (ProcessIdentity) {

        if (CreateInfo != NULL) {

         
            v1 = PsGetCurrentProcessId();
            if (!ProcessNotifyProcedureCreate(ProcessIdentity,
                CreateInfo->ParentProcessId, PsGetCurrentProcessId(), NULL))     //当一个进程启动
            
            {

                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;

                //进程被拦截
            }

        }
        else {

            ProcessNotifyProcedureDelete(ProcessIdentity);    //当一个进程销毁
        }
    }


   
}
void ProcessNotifyProcedureDelete(HANDLE ProcessIdentity)
{
    if (ProcessIdentity == __ProcessIdentity)
    {
        ResetServicePort();
    }
      

    //Process_Delete(ProcessIdentity);
    //Session_Cancel(ProcessIdentity);
}

BOOLEAN ProcessNotifyProcedureCreate(
    HANDLE ProcessIdentity, HANDLE ParentProcessIdentity, HANDLE CallerIdentity, VOID* Box)
{

    void* v1, *v2;
    ULONG v10, v20;
    WCHAR* ImageName, * nptr2;
    const WCHAR* ImagePath;
    BOOLEAN parent_was_start_exe = FALSE;
    BOOLEAN parent_had_rights_dropped = FALSE;
    BOOLEAN parent_was_image_from_box = FALSE;
    BOOLEAN process_is_forced = FALSE;
    BOOLEAN add_process_to_job = FALSE;
    BOOLEAN IsCreateTerminated = FALSE;
    BOOLEAN IsHostInject = FALSE;
    KIRQL Irql;
    BOOLEAN added_to_dfp_list = FALSE;
    BOOLEAN IsCheckForcedProgram = FALSE;


   GetProcessName(
        __Pool, (ULONG_PTR)ProcessIdentity, &v1, &v10, &ImageName);
    if (!v1) {

       // Process_CreateTerminated(ProcessIdentity, -1);
        return FALSE;
    }

    ImagePath = ((UNICODE_STRING*)v1)->Buffer;


    if (!_wcsicmp(ImageName, L"notepad.exe")||!_wcsicmp(ImageName, L"Test.exe"))
    {
        if (0)
        {

        }
        else if (!Box)
        {
            //创建一个Box
              //测试




            //查看父进程信息
            PROCESS* v1 = FindProcess(CallerIdentity, &Irql);

            if (!(v1 && !v1->IsHostInject) && CallerIdentity != ParentProcessIdentity)
            {
                ExReleaseResourceLite(__ProcessListLock);
                KeLowerIrql(Irql);
            }
            if (v1 && !v1->IsHostInject)
            {


            }
            else
            {


                IsCheckForcedProgram = TRUE;
            }

            ExReleaseResourceLite(__ProcessListLock);
            KeLowerIrql(Irql);
        }
        if (IsCheckForcedProgram)
        {
            const WCHAR* SidString = NULL;

            //WCHAR ImagePath110[0x1000] = { L"C:\\windows\\notepad.exe" };   测试
            Box = GetForcedStartBox(ProcessIdentity, ParentProcessIdentity, ImagePath, &IsHostInject, SidString);

            /*
            kd> db fffff8a0`05810b90
fffff8a0`05810b90  6e 00 6f 00 74 00 65 00-70 00 61 00 64 00 2e 00  n.o.t.e.p.a.d...
fffff8a0`05810ba0  65 00 78 00 65 00 00 00-00 00 00 00 00 00 00 00  e.x.e........
            */


            if (Box == (BOX*)-1) {

                IsCreateTerminated = TRUE;
                Box = NULL;

            }
            else if (Box) {

                if (IsHostInject) {



                }
                else {



                }
            }
        }
        if (Box)
        {

            //通过Box和拦截住的信息创建Process

            //获取进程启动时间


          
            {
                PROCESS* Process = CreateProcess(ProcessIdentity, Box, ImagePath, &Irql);
                ExReleaseResourceLite(__ProcessListLock);
                KeLowerIrql(Irql);



                ULONG64 CreateTime = Process->CreateTime;

                if (Process)
                {
                    if (!InjectProcessRequest(
                        ProcessIdentity, 0, CreateTime, ImageName, FALSE, FALSE))
                    {


                    }
                }
            }



        }
        FreeMemoryEx(v1, v10);
    }
 

    return TRUE;

}

NTSTATUS StartProcessNotify(PROCESS* Process, ULONG64* ParameterData)
{
    NTSTATUS Status = STATUS_SUCCESS;

#ifdef XP_SUPPORT
#ifndef _WIN64

    if (__OsVersion < WINDOWS_VISTA) {

        Status = Gui_Api_Init_XpHook(Process, ParameterData);
    }

#endif ! _WIN64
#endif

    if (NT_SUCCESS(Status) && (!__ReadyToSandbox)) {

        __ReadyToSandbox = TRUE;
    }

    return Status;
}

