#include "ObjectHook.h"
#include "ObjectHelper.h"
#include "ThreadHelper.h"
#include "HookHelper.h"
#include "StatusHelper.h"
#include "MemoryHelper.h"
#include "MemoryHook.h"

#include "dllmain.h"




LPFN_NTQUERYOBJECT          __sys_NtQueryObject = NULL;
LPFN_NTCREATEEVENT          __sys_NtCreateEvent = NULL;
LPFN_NTOPENEVENT            __sys_NtOpenEvent = NULL;
LPFN_NTCREATEDIRECTORYOBJECT    __sys_NtCreateDirectoryObject = NULL;
LPFN_NTOPENDIRECTORYOBJECT      __sys_NtOpenDirectoryObject = NULL;

BOOLEAN ObjectHook(void)
{
    HMODULE ModuleHandle = __Ntdll;

#if 0
    __sys_NtQueryObject = NtQueryObject;
#else
    DLL_HOOK(Detour, NtQueryObject);
    /*
    0:000> u NtQueryObject
ntdll!NtQueryObject:
00000000`77bf13b0 ff254aec7eff    jmp     qword ptr [00000000`773e0000]
00000000`77bf13b6 0000            add     byte ptr [rax],al
00000000`77bf13b8 0f05            syscall
00000000`77bf13ba c3              ret
00000000`77bf13bb 0f1f440000      nop     dword ptr [rax+rax]

    0:000> dq 00000000`773e0000
00000000`773e0000  000007fe`f13e1159

    0:000> u 000007fe`f13e1159
Dll!ILT+340(?DetourNtQueryObjectYAJPEAXW4_OBJECT_INFORMATION_CLASS:
000007fe`f13e1159 e982560000      jmp     Dll!DetourNtQueryObject (000007fe`f13e67e0)



    0:000> dq __sys_NtQueryObject
000007fe`f3f13278  000007ff`fff80218 00000000`00000100

    0:000> u 000007ff`fff80218
000007ff`fff80218 4c8bd1          mov     r10,rcx
000007ff`fff8021b b80d000000      mov     eax,0Dh
000007ff`fff80220 0f05            syscall
000007ff`fff80222 c3              ret
000007ff`fff80223 0f1f440000      nop     dword ptr [rax+rax]
000007ff`fff80228 ff25e2ffffff    jmp     qword ptr [000007ff`fff80210]


    0:000> dq 000007ff`fff80210
000007ff`fff80210  00000000`77bf13c0

    0:000> u 00000000`77bf13c0
ntdll!NtQueryInformationFile:
00000000`77bf13c0 4c8bd1          mov     r10,rcx
00000000`77bf13c3 b80e000000      mov     eax,0Eh
00000000`77bf13c8 0f05            syscall
00000000`77bf13ca c3              ret
00000000`77bf13cb 0f1f440000      nop     dword ptr [rax+rax]

    */


    DLL_HOOK(Detour,NtQueryVirtualMemory);
#endif


    /*
    if (!Dll_CompartmentMode) // NoDriverAssist
        obj_use_driver_obj_lookup = SbieApi_QueryConfBool(NULL, L"UseDriverObjLookup", FALSE);*/

    return TRUE;
}

NTSTATUS DetourNtQueryObject(
    HANDLE ObjectHandle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    void* ObjectInformation,
    ULONG Length,
    ULONG* ResultLength)
{
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING* Name;
    ULONG NameType;
    ULONG LastError;
    ULONG MaxLength;
    ULONG ReturnLength;
    THREAD_DATA* ThreadData = GetTlsData(&LastError);   //线程 存储




    if (ThreadData->NtQueryObjectLock ||
        ObjectInformationClass != ObjectNameInformation)
    {
       //白名单放行
       return __sys_NtQueryObject(
            ObjectHandle, ObjectInformationClass,
            ObjectInformation, Length, ResultLength);
    }
    ThreadData->NtQueryObjectLock = TRUE;

    NameType = DetourGetObjectType(ObjectHandle);      //通过句柄获取对象类型



    if (NameType != OBJ_TYPE_FILE && NameType != OBJ_TYPE_KEY &&
        NameType != OBJ_TYPE_DIRECTORY && NameType != OBJ_TYPE_PORT &&
        NameType != OBJ_TYPE_EVENT && NameType != OBJ_TYPE_MUTANT &&
        NameType != OBJ_TYPE_SECTION && NameType != OBJ_TYPE_SEMAPHORE) {

        Status = __sys_NtQueryObject(
            ObjectHandle, ObjectInformationClass,
            ObjectInformation, Length, ResultLength);

        goto Exit;
    }

    //通过对象获取对象名称
    if (Length) {
        Name = (UNICODE_STRING*)ObjectInformation;
        MaxLength = Length & ~1;
    }
    else {
        MaxLength = sizeof(OBJECT_NAME_INFORMATION) + 32;
        Name = (UNICODE_STRING*)MemoryPoolAllocateEx(__Pool10,MaxLength);
    }

    Status = __sys_NtQueryObject(
        ObjectHandle, ObjectNameInformation, Name, MaxLength, &ReturnLength);

    if (Status == STATUS_INFO_LENGTH_MISMATCH ||
        Status == STATUS_BUFFER_OVERFLOW) {

        if (Name != ObjectInformation)
            MemoryPoolFreeEx(Name);
        MaxLength = ReturnLength;
        Name = (UNICODE_STRING*)MemoryPoolAllocateEx(__Pool10, MaxLength);

        Status = __sys_NtQueryObject(
            ObjectHandle, ObjectNameInformation, Name, MaxLength, &ReturnLength);
    }
    if (!NT_SUCCESS(Status)) {

        if (Name != ObjectInformation)
            MemoryPoolFreeEx(Name);

        Status = __sys_NtQueryObject(
            ObjectHandle, ObjectInformationClass,
            ObjectInformation, Length, ResultLength);

        goto Exit;
    }

    //
    // fix path to remove sandbox prefix
    //

    if (Name->Length) {

        ULONG v1 = 0;

        if (NameType == OBJ_TYPE_FILE)
        {
            //过滤处理
        }

        else if (NameType == OBJ_TYPE_KEY)
        {

        }
        else
        {

        }

        if (v1)
        {

        }
           
    }
    if (ResultLength)
        *ResultLength = ReturnLength;

    if (Length < ReturnLength) {

        if (Length < sizeof(UNICODE_STRING))
            Status = STATUS_INFO_LENGTH_MISMATCH;
        else
            Status = STATUS_BUFFER_OVERFLOW;

    }
    else if (Name != ObjectInformation) {

        UNICODE_STRING* v1 = (UNICODE_STRING*)ObjectInformation;
        memcpy(v1, Name, ReturnLength);
        v1->Buffer = (WCHAR*)(v1 + 1);
    }

    if (Name != ObjectInformation)
        MemoryPoolFreeEx(Name);

Exit:

    ThreadData->NtQueryObjectLock = FALSE;

    SetLastError(LastError);
    return Status;;
}





ULONG DetourGetObjectType(HANDLE ObjectHandle)
{
    NTSTATUS Status;
    union {
        PUBLIC_OBJECT_TYPE_INFORMATION PublicObjectTypeInfo;
        wchar_t Buffer[256];
    } u;

    ULONG Length = sizeof(u.Buffer);

    Status = __sys_NtQueryObject(ObjectHandle, ObjectTypeInformation, &u.PublicObjectTypeInfo, Length, &Length);

    if (NT_SUCCESS(Status))
    {
        const WCHAR* TypeName = u.PublicObjectTypeInfo.TypeName.Buffer;
        if (TypeName[0] == L'D' && _wcsicmp(TypeName, L"Directory") == 0)
            return OBJ_TYPE_DIRECTORY;
        if (TypeName[0] == L'F' && _wcsicmp(TypeName, L"File") == 0)
            return OBJ_TYPE_FILE;
        if (TypeName[0] == L'K' && _wcsicmp(TypeName, L"Key") == 0)
            return OBJ_TYPE_KEY;
        if (TypeName[0] == L'A' && _wcsicmp(TypeName, L"ALPC Port") == 0)
            return OBJ_TYPE_PORT;
        if (TypeName[0] == L'P' && _wcsicmp(TypeName, L"Port") == 0)
            return OBJ_TYPE_PORT;
        if (TypeName[0] == L'E' && _wcsicmp(TypeName, L"Event") == 0)
            return OBJ_TYPE_EVENT;
        if (TypeName[0] == L'M' && _wcsicmp(TypeName, L"Mutant") == 0)
            return OBJ_TYPE_MUTANT;
        if (TypeName[0] == L'S' && _wcsicmp(TypeName, L"Section") == 0)
            return OBJ_TYPE_SECTION;
        if (TypeName[0] == L'S' && _wcsicmp(TypeName, L"Semaphore") == 0)
            return OBJ_TYPE_SEMAPHORE;
        if (TypeName[0] == L'P' && _wcsicmp(TypeName, L"Process") == 0)
            return OBJ_TYPE_PROCESS;
    }
    return OBJ_TYPE_UNKNOWN;
}

NTSTATUS  DetourNtCreateEvent(
    HANDLE* EventHandle,
    ACCESS_MASK DesiredAccess,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    EVENT_TYPE EventType,
    BOOLEAN InitialState)
{
    NTSTATUS Status;
    WCHAR* v1;
    WCHAR* v2;
    UNICODE_STRING ObjectName;
    OBJECT_ATTRIBUTES v10;
    if ((!ObjectAttributes) || (!ObjectAttributes->ObjectName)) {

        return __sys_NtCreateEvent(
            EventHandle, DesiredAccess, ObjectAttributes,
            EventType, InitialState);
    }
    __try {

        //v1 命名事件的真实路径
        // 0:000> db 000007ff`fff80b98
        /*
        000007ff`fff80b98  5c 00 53 00 65 00 73 00 - 73 00 69 00 6f 00 6e 00  \.S.e.s.s.i.o.n.
        000007ff`fff80ba8  73 00 5c 00 31 00 5c 00 - 42 00 61 00 73 00 65 00  s.\.1.\.B.a.s.e.
        000007ff`fff80bb8  4e 00 61 00 6d 00 65 00 - 64 00 4f 00 62 00 6a 00  N.a.m.e.d.O.b.j.
        000007ff`fff80bc8  65 00 63 00 74 00 73 00 - 5c 00 47 00 6c 00 6f 00  e.c.t.s.\.G.l.o.
        000007ff`fff80bd8  62 00 61 00 6c 00 5c 00 - 53 00 68 00 69 00 6e 00  b.a.l.\.S.h.i.n.
        000007ff`fff80be8  65 00 00 00 00 00 00 00 - 00 00 00 00 00 00 00 00  e...............*/

        // 
        // 
        //v2 是该事件的沙盒路径

        /*
        0:000> db 000007ff`fff80d08 l 120
        000007ff`fff80d08  5c 00 53 00 61 00 6e 00-64 00 62 00 6f 00 78 00  \.S.a.n.d.b.o.x.
        000007ff`fff80d18  5c 00 25 00 55 00 53 00-45 00 52 00 25 00 5c 00  \.%.U.S.E.R.%.\.
        000007ff`fff80d28  25 00 53 00 41 00 4e 00-44 00 42 00 4f 00 58 00  %.S.A.N.D.B.O.X.
        000007ff`fff80d38  25 00 5c 00 53 00 65 00-73 00 73 00 69 00 6f 00  %.\.S.e.s.s.i.o.
        000007ff`fff80d48  6e 00 5f 00 25 00 53 00-45 00 53 00 53 00 49 00  n._.%.S.E.S.S.I.
        000007ff`fff80d58  4f 00 4e 00 25 00 5c 00-53 00 65 00 73 00 73 00  O.N.%.\.S.e.s.s.
        000007ff`fff80d68  69 00 6f 00 6e 00 73 00-5c 00 31 00 5c 00 42 00  i.o.n.s.\.1.\.B.
        000007ff`fff80d78  61 00 73 00 65 00 4e 00-61 00 6d 00 65 00 64 00  a.s.e.N.a.m.e.d.
        000007ff`fff80d88  4f 00 62 00 6a 00 65 00-63 00 74 00 73 00 5c 00  O.b.j.e.c.t.s.\.
        000007ff`fff80d98  47 00 6c 00 6f 00 62 00-61 00 6c 00 5c 00 53 00  G.l.o.b.a.l.\.S.
        000007ff`fff80da8  68 00 69 00 6e 00 65 00-00 00 00 00 00 00 00 00  h.i.n.e.........
        */



        Status = GetName2(ObjectAttributes, &v1, &v2, L"CreateEvent");
        if (!NT_SUCCESS(Status))
            __leave;

        if (!NT_SUCCESS(Status))
            __leave;

        InitializeObjectAttributes(&v10,&ObjectName, OBJECT_ATTRIBUTES_ATTRIBUTES, NULL, NULL);
        if (!v1) {


            //请求驱动

            Status = __sys_NtCreateEvent(
                EventHandle, DesiredAccess, ObjectAttributes,
                EventType, InitialState);

            __leave;
        }


        RtlInitUnicodeString(&ObjectName, v2);

        Status = __sys_NtCreateEvent(
            EventHandle, DesiredAccess, &v10,
            EventType, InitialState);

        if (Status == STATUS_OBJECT_PATH_NOT_FOUND) 
        {

          
            Status = CreatePath(v1, v2);

            if (NT_SUCCESS(Status)) {
                Status = __sys_NtCreateEvent(
                    EventHandle, DesiredAccess, &v10,
                    EventType, InitialState);
            }
        }


    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    return Status;
}


NTSTATUS DetourNtOpenEvent(
    HANDLE* EventHandle,
    ACCESS_MASK DesiredAccess,
    OBJECT_ATTRIBUTES* ObjectAttributes)
{


    NTSTATUS Status;

    Status = __sys_NtOpenEvent(
        EventHandle, DesiredAccess, ObjectAttributes);

    return Status;
}

NTSTATUS DetourNtOpenDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes)
{
    return  __sys_NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS DetourNtCreateDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes)
{
    ULONG LastError;
    THREAD_DATA* ThreadData;

    NTSTATUS Status;
    OBJECT_ATTRIBUTES v1;
    UNICODE_STRING v2;
    WCHAR* TruePath;
    WCHAR* CopyPath;
    ULONG mp_flags;

    //
    // shortcut processing when object name is not specified
    //

    return __sys_NtCreateDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);
}
   
