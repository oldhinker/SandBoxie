#include "ProcessForce.h"
#include "MemoryList.h"
#include "ProcessHelper.h"
#include "FileHelper.h"
#include "MemoryHelper.h"
BOX* GetForcedStartBox(
    HANDLE ProcessIdentity, HANDLE ParentProcessIdentity, const WCHAR* ImagePath, BOOLEAN* IsHostInject, const WCHAR* SidString)
{
    NTSTATUS Status;
    ULONG SessionIdentity;
    UNICODE_STRING SidString2;
    WCHAR* ImagePath2 = L"";
    ULONG PathLength2;
    const WCHAR* ImageName2 = L"";

    PEPROCESS ProcessObject;
    WCHAR* CurrentDirectory, * DocArgument;
    ULONG DirectoryLength, ArgumentLength;
    LIST Boxes;
    BOX* Box;
    ULONG alert;
    BOOLEAN IsCheckForce;
    BOOLEAN is_start_exe;
    BOOLEAN image_sbie;
    BOOLEAN force_alert;
    BOOLEAN dfp_already_added;
    BOOLEAN same_image_name;

    void* v5 = NULL;
    ULONG v7 = 0;
    WCHAR* ParentName = NULL;
    WCHAR* ParentPath = NULL;

    IsCheckForce = TRUE;


    //获取进程对象
    ProcessObject = GetProcessObject(ProcessIdentity, &SidString2, &SessionIdentity);


    if (!SidString)
        SidString = SidString2.Buffer;   //返回值

    if (!ProcessObject)
        return NULL;


    //系统判断





    Status = TranslateDosToNt(
        ImagePath, &ImagePath2, &PathLength2);

    /*
    kd> db fffff880`0480ed50
fffff880`0480ed50  43 00 3a 00 5c 00 77 00-69 00 6e 00 64 00 6f 00  C.:.\.w.i.n.d.o.
fffff880`0480ed60  77 00 73 00 5c 00 6e 00-6f 00 74 00 65 00 70 00  w.s.\.n.o.t.e.p.
fffff880`0480ed70  61 00 64 00 2e 00 65 00-78 00 65 00 00 00 00 00  a.d...e.x.e....
    
    kd> db fffff8a0`05810b50
fffff8a0`05810b50  5c 00 44 00 65 00 76 00-69 00 63 00 65 00 5c 00  \.D.e.v.i.c.e.\.
fffff8a0`05810b60  48 00 61 00 72 00 64 00-64 00 69 00 73 00 6b 00  H.a.r.d.d.i.s.k.
fffff8a0`05810b70  56 00 6f 00 6c 00 75 00-6d 00 65 00 31 00 5c 00  V.o.l.u.m.e.1.\.
fffff8a0`05810b80  77 00 69 00 6e 00 64 00-6f 00 77 00 73 00 5c 00  w.i.n.d.o.w.s.\.
fffff8a0`05810b90  6e 00 6f 00 74 00 65 00-70 00 61 00 64 00 2e 00  n.o.t.e.p.a.d...
fffff8a0`05810ba0  65 00 78 00 65 00 00 00-00 00 00 00 00 00 00 00  e.x.e...........

    
    */

    if (NT_SUCCESS(Status)) {

        ImageName2 = wcsrchr(ImagePath2, L'\\');
        if (ImageName2 && ImageName2[1])
            ++ImageName2;
        else
            Status = STATUS_OBJECT_PATH_SYNTAX_BAD;     // random
    }
    if (!NT_SUCCESS(Status)) {

        RtlFreeUnicodeString(&SidString);
        ObDereferenceObject(ProcessObject);
        return NULL;
    }

    //
    // initialize ParentName but only if the parent is not a system process
    // 

    if (!IsProcessRunningAsSystemAccount(ParentProcessIdentity)) {

        GetProcessName(
            __Pool, (ULONG_PTR)ParentProcessIdentity, &v5, &v7, &ParentName);
        if (v5)
            ParentPath = ((UNICODE_STRING*)v5)->Buffer;
    }

    GetCurrentDirectory(ProcessObject, &CurrentDirectory, &DirectoryLength);
    //0xfffff8a0`03ef7050 "\Device\HarddiskVolume1\Program Files (x86)\Windows Kits\10\Debuggers\x"

    GetDocArgument(ProcessObject, &DocArgument, &ArgumentLength);   //  +0x070 CommandLine      : _UNICODE_STRING




    Box = NULL;
   

    CreateForceData(&Boxes, SidString, SessionIdentity);




    if (IsCheckForce) {

        Box = CheckBoxPath(&Boxes, ImagePath2);   //调试 0xfffff8a0`0fb3a7c0 "\Device\HarddiskVolume1\Windows\System32\notepad.exe"

    



    
    
    }

    DeleteForceData(&Boxes);


    if (v5)
        FreeMemoryEx(v5, v7);

    if (DocArgument)
        FreeMemoryEx(DocArgument, ArgumentLength);

    if (CurrentDirectory)
        FreeMemoryEx(CurrentDirectory, DirectoryLength);

    FreeMemoryEx(ImagePath2, PathLength2);

    RtlFreeUnicodeString(&SidString2);
    ObDereferenceObject(ProcessObject);

    return Box;


}



void CreateForceData(
    LIST* Boxes, const WCHAR* SidString, ULONG SessionIdentity)
{
  
    FORCE_BOX* ForceBox;
    const WCHAR* Section = L"SandBox";     //测试
    //
    // scan list of boxes and create FORCE_BOX elements
    //

    InitializeList(Boxes);

    while (1) {

     

        ForceBox = MemoryPoolAllocate(__Pool, sizeof(FORCE_BOX));
        if (!ForceBox)
            break;

        ForceBox->Box = CreateBox(
            __Pool, Section, SidString, SessionIdentity, TRUE);    //动态申请
        if (!ForceBox->Box) {
            MemoryPoolFree(ForceBox, sizeof(FORCE_BOX));
            continue;
        }

      
        InsertAfter(Boxes, NULL, ForceBox);



        break;

       
    }


}

void DeleteForceData(LIST* Boxes)
{
    FORCE_BOX* Box;

    while (1) {

        Box = GetListHead(Boxes);
        if (!Box)
            break;

        RemoveCurrent(Boxes, Box);

        /*
        Process_DeleteForceDataFolders(&box->ForceFolder);
        //Process_DeleteForceDataProcesses(&box->ForceProcess);
        Process_DeleteForceDataFolders(&box->ForceProcess);
        //Process_DeleteForceDataProcesses(&box->ForceChildren);
        Process_DeleteForceDataFolders(&box->ForceChildren);
        Process_DeleteForceDataFolders(&box->AlertFolder);
        //Process_DeleteForceDataProcesses(&box->AlertProcess);
        Process_DeleteForceDataFolders(&box->AlertProcess);
        Process_DeleteForceDataProcesses(&box->HostInjectProcess);*/

        FreeBox(Box->Box);

        FreeMemoryEx(Box, sizeof(FORCE_BOX));
    }
}







BOX* CheckBoxPath(LIST* Boxes, const WCHAR* ImagePath)
{
    UNICODE_STRING v1;
    FORCE_BOX* ForceBox;

    RtlInitUnicodeString(&v1, ImagePath);

    ForceBox = GetListHead(Boxes);
    while (ForceBox) {



        return ForceBox->Box;    //测试
        /*
        if (Box_IsBoxedPath(ForceBox->Box, file, &v1))
            return ForceBox->Box;*/

        ForceBox = GetNextNode(ForceBox);
    }

    return NULL;
}