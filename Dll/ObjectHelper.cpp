#include "ObjectHelper.h"
#include "StatusHelper.h"
#include "ThreadHelper.h"
#include "ObjectHook.h"
#include "ApiHelper.h"
#include "dllmain.h"

BOOLEAN __IsUseDriverLookup = FALSE;

NTSTATUS GetName(
    HANDLE RootDirectory, UNICODE_STRING* ObjectName,
    WCHAR** TruePath, WCHAR** CopyPath, BOOLEAN* IsBoxedPath)
{
 
    NTSTATUS Status;
    ULONG v7;
    WCHAR* v5;
    ULONG  Length;
    WCHAR* Buffer;

    *TruePath = NULL;
    *CopyPath = NULL;


    THREAD_DATA* ThreadData = GetTlsData(NULL);

    if (IsBoxedPath)
        *IsBoxedPath = FALSE;

    if (ObjectName && ObjectName != (UNICODE_STRING*)-1) {
        Length = ObjectName->Length & ~1;
        Buffer = ObjectName->Buffer;

    }
    else {
        Length = 0;
        Buffer = NULL;
    }

    //
    // if a root handle is specified, we query the full name of the
    // root key, and append the ObjectName
    //

    if (RootDirectory) 
    {
        v7 = 256;
        v5 = GetTlsNameBuffer(
            ThreadData, TRUE_NAME_BUFFER, v7 + Length);    //在源数据基础增加256个字节


        if (((!Length) || (!*Buffer)) && ObjectName != (UNICODE_STRING*)-1) {

            //
            // an object handle was specified, but the object name is an
            // empty string or NULL.  if the handle is for a directory
            // object, then we treat this as an unnamed object, otherwise
            // we go on as usual
            //

            if (GetObjectType(RootDirectory) == OBJ_TYPE_DIRECTORY)
            {

                *TruePath = NULL;
                *CopyPath = NULL;

                return STATUS_SUCCESS;
            }
        }

        if (Length && *Buffer == L'\\') {

            //
            // if the caller specifies both a directory and an object
            // name that begins with a backslash, return special status
            //

            return STATUS_OBJECT_PATH_SYNTAX_BAD;
        }

        //获取到了对象名称
        Status = GetObjectName(RootDirectory, v5, &v7);
        /*
        0:000> dt _unicode_string 000007ff`fff80b88
        ntdll!_UNICODE_STRING
        "\Sessions\1\BaseNamedObjects"
        +0x000 Length           : 0x38
        +0x002 MaximumLength    : 0x3a
        +0x008 Buffer           : 0x000007ff`fff80b98  "\Sessions\1\BaseNamedObjects"
        */

        if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_INFO_LENGTH_MISMATCH) {

            v5 = GetTlsNameBuffer(
                ThreadData, TRUE_NAME_BUFFER, v7 + Length);

            Status = GetObjectName(RootDirectory, v5, &v7);
        }
        if (!NT_SUCCESS(Status))
            return Status;

        *TruePath = ((OBJECT_NAME_INFORMATION*)v5)->Name.Buffer;
        /*
        0:000> db 000007ff`fff80b98   TruePath
        000007ff`fff80b98  5c 00 53 00 65 00 73 00-73 00 69 00 6f 00 6e 00  \.S.e.s.s.i.o.n.
        000007ff`fff80ba8  73 00 5c 00 31 00 5c 00-42 00 61 00 73 00 65 00  s.\.1.\.B.a.s.e.
        000007ff`fff80bb8  4e 00 61 00 6d 00 65 00-64 00 4f 00 62 00 6a 00  N.a.m.e.d.O.b.j.
        000007ff`fff80bc8  65 00 63 00 74 00 73 00-00 00 00 00 00 00 00 00  e.c.t.s.........
        */

        if (!*TruePath) {

            //
            // object attributes indicate an unnamed parent directory
            //

            *TruePath = NULL;
            return Status;
        }
        v5 = (*TruePath)
            + ((OBJECT_NAME_INFORMATION*)v5)->Name.Length
            / sizeof(WCHAR);

        if (Length) {

            *v5 = L'\\';
            ++v5;
            memcpy(v5, Buffer, Length);

            v5 += Length / sizeof(WCHAR);
        }

        *v5 = L'\0';

        /*
        0:000> db 000007ff`fff80b98   TruePath
        000007ff`fff80b98  5c 00 53 00 65 00 73 00-73 00 69 00 6f 00 6e 00  \.S.e.s.s.i.o.n.
        000007ff`fff80ba8  73 00 5c 00 31 00 5c 00-42 00 61 00 73 00 65 00  s.\.1.\.B.a.s.e.
        000007ff`fff80bb8  4e 00 61 00 6d 00 65 00-64 00 4f 00 62 00 6a 00  N.a.m.e.d.O.b.j.
        000007ff`fff80bc8  65 00 63 00 74 00 73 00-5c 00 47 00 6c 00 6f 00  e.c.t.s.\.G.l.o.
        000007ff`fff80bd8  62 00 61 00 6c 00 5c 00-53 00 68 00 69 00 6e 00  b.a.l.\.S.h.i.n.
        000007ff`fff80be8  65 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  e...............

        
        */

      
    }
    else if (Length) 
    {
        v5 = GetTlsNameBuffer(ThreadData, TRUE_NAME_BUFFER, Length);

        *TruePath = v5;

        memcpy(v5, Buffer, Length);

        v5 += Length / sizeof(WCHAR);
        *v5 = L'\0';
    }
    else {

        *TruePath = NULL;
        *CopyPath = NULL;

        return STATUS_SUCCESS;
    }

    //
    // for 32-bit Internet Explorer running on 64-bit Windows 7 (Wow64),
    // check for SplWow64 resources, and adjust the integrity level
    // which is the last digit of the resource name.
    //
    // - always 1 if we are running as a standard user (note that outside
    // the sandbox, IE low integrity processes use integrity level 0)
    // - always 2 if we are running as an elevated user
    //
    // this is necessary due Internet Explorer assuming it is going to
    // run with low integrity, while in fact it runs with medium integrity
    // inside the sandbox, and Secure_NtQueryInformationToken will fake
    // a high integrity result
    //
    // on Sandboxie 4 with highly restricted process token, we always need
    // to adjust the SplWow64 object path
    //

   




    v7 = wcslen(*TruePath);


CheckSandboxPrefix:

   
    if (v7 >= __BoxIpcPathLength &&
        0 == NlsStrCmp(
            *TruePath, __BoxIpcPathData, __BoxIpcPathLength))
    {
        *TruePath += __BoxIpcPathLength;
        v7 -= __BoxIpcPathLength;
        if (IsBoxedPath)
            *IsBoxedPath = TRUE;

        goto CheckSandboxPrefix;
    }

    v5 = GetTlsNameBuffer(
        ThreadData, COPY_NAME_BUFFER, __BoxIpcPathLength + v7);

    *CopyPath = v5;

    {
        wmemcpy(v5, __BoxIpcPathData, __BoxIpcPathLength);
        v5 += __BoxIpcPathLength;

        wmemcpy(v5, *TruePath, v7);
        v5 += v7;
    }

    *v5 = L'\0';
    

    return STATUS_SUCCESS;
}

NTSTATUS GetName2(
    OBJECT_ATTRIBUTES* ObjectAttributes,
    WCHAR** TruePath, WCHAR** CopyPath,
    const WCHAR* ServiceName)
{
    NTSTATUS Status;
    HANDLE RootDirectory;
    UNICODE_STRING* ObjectName;

    if (ObjectAttributes) {

        RootDirectory = ObjectAttributes->RootDirectory;
        ObjectName = ObjectAttributes->ObjectName;

    }
    else {

        RootDirectory = NULL;
        ObjectName = NULL;
    }

    Status = GetName(
        RootDirectory, ObjectName, TruePath, CopyPath, NULL);

    if (NT_SUCCESS(Status))
    {

    }

    return Status;
}



NTSTATUS GetObjectName(
    HANDLE ObjectHandle, void* ObjectName, ULONG* Length)
{
    NTSTATUS Status;

    //
    // NtQueryObject is known for locking up forever when queried for object name on a pipe handle 
    // opened for synchronous io, and where there are pending read operations.
    // 
    // To remedy this we ask the driver to lookup the objects name instead
    // 

    if (__IsUseDriverLookup) 
    {
        OBJECT_NAME_INFORMATION* ObjectNameInfo = (OBJECT_NAME_INFORMATION*)ObjectName;

        wchar_t* v5 = (wchar_t*)((UCHAR*)ObjectName + sizeof(OBJECT_NAME_INFORMATION));
        ULONG v7 = *Length - sizeof(OBJECT_NAME_INFORMATION);

        Status = GetFileName(ObjectHandle, v5, &v7, NULL);

        if (NT_SUCCESS(Status)) {
            ObjectNameInfo->Name.Buffer = v5;
            ObjectNameInfo->Name.Length = wcslen(v5) * sizeof(wchar_t);
            ObjectNameInfo->Name.MaximumLength = (USHORT)v7;


            /*
            0:000> dt _unicode_string 000007ff`fff80b88
            ntdll!_UNICODE_STRING
            "\Sessions\1\BaseNamedObjects"
            +0x000 Length           : 0x38
            +0x002 MaximumLength    : 0x3a
            +0x008 Buffer           : 0x000007ff`fff80b98  "\Sessions\1\BaseNamedObjects"
            
            */
        }
    
    }
    else {

        THREAD_DATA* ThreadData = GetTlsData(NULL);

        ThreadData->NtQueryObjectLock = TRUE;

        Status = __sys_NtQueryObject(
            ObjectHandle, ObjectNameInformation, ObjectName, *Length, Length);

        ThreadData->NtQueryObjectLock = FALSE;


        /*
        0:000> dt _unicode_string 0x000007ff`fff80b88
        ntdll!_UNICODE_STRING
        "\Sessions\1\BaseNamedObjects"
        +0x000 Length           : 0x38
        +0x002 MaximumLength    : 0x3a
        +0x008 Buffer           : 0x000007ff`fff80b98  "\Sessions\1\BaseNamedObjects"
        
        */


    }

    return Status;
}



NTSTATUS CreatePath(WCHAR* TruePath, WCHAR* CopyPath)
{
    NTSTATUS Status;
    HANDLE DirectoryHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING ObjectName;
    WCHAR* Backslash;

    //if (Dll_AlernateIpcNaming)
    //    return STATUS_OBJECT_PATH_NOT_FOUND;

    //
    // open the TruePath object directory containing the object
    // for which we got STATUS_OBJECT_PATH_NOT_FOUND
    //

    Backslash = wcsrchr(TruePath, L'\\');
    if (!Backslash)
        return STATUS_OBJECT_PATH_NOT_FOUND;

    *Backslash = L'\0';

    InitializeObjectAttributes(
        &ObjectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    RtlInitUnicodeString(&ObjectName, TruePath);

    Status = __sys_NtOpenDirectoryObject(&DirectoryHandle, DIRECTORY_QUERY, &ObjectAttributes);

    *Backslash = L'\\';

    if (!NT_SUCCESS(Status))
        return Status;

    NtClose(DirectoryHandle);

    //
    // create the parent directories along the CopyPath
    //



    Backslash = CopyPath;

    while (1) {

        Backslash = wcschr(Backslash + 1, L'\\');
        if (!Backslash)
            break;

        if ((ULONG)(Backslash - CopyPath) > __BoxIpcPathLength) {

            *Backslash = L'\0';

            Status = CreateDirOrLink(CopyPath, NULL);

            *Backslash = L'\\';

            if (!NT_SUCCESS(Status))
                return Status;
        }
    }
 
    return STATUS_SUCCESS;
}