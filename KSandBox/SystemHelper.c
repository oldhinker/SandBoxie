#include "SystemHelper.h"
#include "ProcessHelper.h"
#include "ApiHelper.h"
#include "ObjectHelper.h"
#include "MemoryLock.h"
#include "PeHelper.h"
#include "Syscall.h"
#include "MemoryList.h"
#include "ApiHelper.h"


ULONG __OsVersion = 0;
ULONG __OsBuild = 0;
WCHAR* __HomePath2 = NULL;   //DosPath
WCHAR* __HomePath1 = NULL;   //NtPah
ULONG __PathLength1 = 0;

BOOLEAN InitializeSyscalls()
{

    if (!GetSystemServiceInfo())  //Ntdll.dll 获取服务索引 从而获取 Nt函数的地址
        return FALSE;


    if (!GetSystemServiceCode())
        return FALSE;
    SetCommonService(QUERY_SYSCALLS, QuerySyscalls);



}
ULONG_PTR GetNtosKrnl(void)
{
    NTSTATUS Status;

    UCHAR* v5;
    ULONG ReturnLength;
    ULONG_PTR NtosKrnl;

    v5 = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, TAG);
    if (!v5) {

      
        return 0;
    }

    ReturnLength = 0;
    Status = ZwQuerySystemInformation(
        SystemModuleInformation, v5, PAGE_SIZE, &ReturnLength);

    if (Status != STATUS_SUCCESS &&
        Status != STATUS_INFO_LENGTH_MISMATCH) {

        ExFreePoolWithTag(v5, TAG);
        return 0;
    }

    NtosKrnl = ((SYSTEM_MODULE_INFORMATION*)v5)->SystemModuleEntry[0].ImageBaseAddress;

    ExFreePoolWithTag(v5, TAG);

    return NtosKrnl;
}

BOOLEAN CheckOsVersion(void)
{
    ULONG MajorVersion, MinorVersion;
    WCHAR str[64];
    //
    // make sure we're running on Windows XP (v5.1) or later (32-bit)
    // or Windows 7 (v6.1) or later (64-bit)
    //

#if defined(_WIN64) || !defined(XP_SUPPORT)
    const ULONG MajorVersionMin = 6;
    const ULONG MinorVersionMin = 1;
#else
    const ULONG MajorVersionMin = 5;
    const ULONG MinorVersionMin = 1;
#endif

    PsGetVersion(&MajorVersion, &MinorVersion, &__OsBuild, NULL);

    if (MajorVersion > MajorVersionMin ||
        (MajorVersion == MajorVersionMin
            && MinorVersion >= MinorVersionMin)) {

        if (MajorVersion == 10) { // for windows 11 its still 10
            __OsVersion = WINDOWS_10;
        }
        else if (MajorVersion == 6) {

            if (MinorVersion == 3 && __OsBuild >= 9600) {
                __OsVersion = WINDOWS_81;
            }
            else if (MinorVersion == 2 && __OsBuild >= 9200) {
                __OsVersion = WINDOWS_8;
            }

            else if (MinorVersion == 1 && __OsBuild >= 7600) {
                __OsVersion = WINDOWS_7;
            }
            else if (MinorVersion == 0 && __OsBuild >= 6000) {
                __OsVersion = WINDOWS_VISTA;
            }

        }
        else {
            if (MinorVersion == 2)
                __OsVersion = WINDOWS_2003;

            else if (MinorVersion == 1)
                __OsVersion = WINDOWS_XP;
        }

        if (__OsVersion)
            return TRUE;
    }
    return FALSE;
}

BOOLEAN CheckHomePath(UNICODE_STRING* RegistryPath)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING v1;
    HANDLE KeyHandle;
    union {
        KEY_VALUE_PARTIAL_INFORMATION Value1;
        WCHAR Value2[256];
    }v2;
    WCHAR PathData[384];
    WCHAR* v3;
    ULONG v7;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_OBJECT* FileObject;
    OBJECT_NAME_INFORMATION* ObjectNameInfo = NULL;
    ULONG NameLength = 0;

    //
    // find the path to SbieDrv.sys
    //

    InitializeObjectAttributes(&ObjectAttributes,
        RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
    
        return FALSE;
    }

    InitializeObjectAttributes(&ObjectAttributes,
        &v1, OBJ_CASE_INSENSITIVE, NULL, NULL);

    RtlInitUnicodeString(&v1, L"ImagePath");
    v7 = sizeof(v2);
    Status = ZwQueryValueKey(
        KeyHandle, &v1, KeyValuePartialInformation, &v2, v7, &v7);

    ZwClose(KeyHandle);

    if (!NT_SUCCESS(Status)) {
       
        return FALSE;
    }
    if ((v2.Value1.Type != REG_SZ && v2.Value1.Type != REG_EXPAND_SZ)
        || v2.Value1.DataLength < 4) {
  
        return FALSE;
    }

    // the path should be \??\<home>\SbieDrv.sys, where <home> is the
    // Sandboxie installation directory.  We need to remove Sandbox.sys,
    // and prepend \??\ if it's missing

    v3 = (WCHAR*)v2.Value1.Data;
    v3[v2.Value1.DataLength / sizeof(WCHAR) - 1] = L'\0';

    if (*v3 != L'\\') {
        wcscpy(PathData, L"\\??\\");
        wcscat(PathData, v3);
    }
    else
        wcscpy(PathData, v3);

    v3 = wcsrchr(PathData, L'\\');
    if (v3)
        *v3 = L'\0';

    __HomePath2 = AllocateStringEx(__Pool, PathData, TRUE);
    if (!__HomePath2) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
      
        return FALSE;
    }

    //
    // try to open the path so we can get a FILE_OBJECT for it
    //

    RtlInitUnicodeString(&v1, PathData);

    InitializeObjectAttributes(&ObjectAttributes,
        &v1, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwCreateFile(
        &KeyHandle,
        FILE_GENERIC_READ,      // DesiredAccess
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,                   // AllocationSize
        0,                      // FileAttributes
        FILE_SHARE_READ,        // ShareAccess
        FILE_OPEN,              // CreateDisposition
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);               // EaBuffer, EaLength

    if (!NT_SUCCESS(Status)) {
      
        return FALSE;
    }

    // get the canonical path name from the file object

    Status = ObReferenceObjectByHandle(
        KeyHandle, 0, NULL, KernelMode, &FileObject, NULL);

    if (!NT_SUCCESS(Status)) {
        ZwClose(KeyHandle);
   
        return FALSE;
    }

    Status = GetObjectName(__Pool, FileObject, &ObjectNameInfo, &NameLength);  //通过对象获取对象名称

    ObDereferenceObject(FileObject);
    ZwClose(KeyHandle);

    if (!NT_SUCCESS(Status)) {
    
        return FALSE;
    }

    __HomePath1 = ObjectNameInfo->Name.Buffer;
    __PathLength1 = wcslen(__HomePath1);


    /*
    kd> dq __HomePath1
    fffff880`02f25128  fffff8a0`03da2120 00000000`00000000
    fffff880`02f25138  00000000`00000000 00000000`00000000
    fffff880`02f25148  00000000`00000000 00000000`00000000
    fffff880`02f25158  00000000`00000000 00000000`00000000
    fffff880`02f25168  00000000`00000000 00000000`00000000
    fffff880`02f25178  00000000`00000000 00000000`00000000
    fffff880`02f25188  00000000`00000000 00000000`00000000
    fffff880`02f25198  00000000`00000000 00000000`00000000
    kd> db fffff8a0`03da2120 
    fffff8a0`03da2120  5c 00 44 00 65 00 76 00-69 00 63 00 65 00 5c 00  \.D.e.v.i.c.e.\.
    fffff8a0`03da2130  48 00 61 00 72 00 64 00-64 00 69 00 73 00 6b 00  H.a.r.d.d.i.s.k.
    fffff8a0`03da2140  56 00 6f 00 6c 00 75 00-6d 00 65 00 31 00 5c 00  V.o.l.u.m.e.1.\.
    fffff8a0`03da2150  55 00 73 00 65 00 72 00-73 00 5c 00 53 00 68 00  U.s.e.r.s.\.S.h.
    fffff8a0`03da2160  69 00 6e 00 65 00 5c 00-44 00 65 00 73 00 6b 00  i.n.e.\.D.e.s.k.
    fffff8a0`03da2170  74 00 6f 00 70 00 00 00-00 00 00 00 00 00 00 00  t.o.p...........



    kd> dq __HomePath2
    fffff880`02f25120  fffff8a0`03da20d0 fffff8a0`03da2120
    fffff880`02f25130  00000000`00000000 00000000`00000000
    fffff880`02f25140  00000000`00000000 00000000`00000000
    fffff880`02f25150  00000000`00000000 00000000`00000000
    fffff880`02f25160  00000000`00000000 00000000`00000000
    fffff880`02f25170  00000000`00000000 00000000`00000000
    fffff880`02f25180  00000000`00000000 00000000`00000000
    fffff880`02f25190  00000000`00000000 00000000`00000000
    kd> db fffff8a0`03da20d0
    fffff8a0`03da20d0  5c 00 3f 00 3f 00 5c 00-43 00 3a 00 5c 00 55 00  \.?.?.\.C.:.\.U.
    fffff8a0`03da20e0  73 00 65 00 72 00 73 00-5c 00 53 00 68 00 69 00  s.e.r.s.\.S.h.i.
    fffff8a0`03da20f0  6e 00 65 00 5c 00 44 00-65 00 73 00 6b 00 74 00  n.e.\.D.e.s.k.t.
    fffff8a0`03da2100  6f 00 70 00 00 00 00 00-00 00 00 40 01 00 00 00  o.p........@....

    
    */

    return TRUE;
}






