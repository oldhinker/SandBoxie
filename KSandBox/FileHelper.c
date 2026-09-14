#include "FileHelper.h"
#include "MemoryPool.h"
#include "ApiHelper.h"
const WCHAR* __Redirector = L"\\Device\\LanmanRedirector";
const ULONG  __RedirectorLength = 24;

const WCHAR* __MupRedir = L"\\Device\\Mup\\;LanmanRedirector";
const ULONG  __MupRedirLength = 29;

const WCHAR* __DfsClientRedir = L"\\Device\\Mup\\DfsClient";
const ULONG  __DfsClientRedirLength = 21;

const WCHAR* __HgfsRedir = L"\\Device\\Mup\\;hgfs";       // VMWare Host Guest File System
const ULONG  __HgfsRedirLength = 17;

const WCHAR* __Mup = L"\\Device\\Mup";
const ULONG  __MupLength = 11;

const WCHAR* File_Device = L"\\Device\\";

const WCHAR* File_NamedPipe = L"\\Device\\NamedPipe";
const ULONG  File_NamedPipeLen = 17;


BOOLEAN InitializeFile(void)
{


    
    SetCommonService(GET_FILE_NAME, GetFileName);
}





NTSTATUS TranslateDosToNt(
    const WCHAR* InPath, WCHAR** OutPath, ULONG* PathLength)
{
    NTSTATUS Status = TranslateDosToNtInternal(
        InPath, __Pool, OutPath, PathLength);

    if (!NT_SUCCESS(Status)) {

        WCHAR* v5;
        ULONG v7;

        if (Status != STATUS_OBJECT_PATH_SYNTAX_BAD)
            return Status;

        v7 = (wcslen(InPath) + 1) * sizeof(WCHAR);
        v5 = MemoryPoolAllocate(__Pool, v7);
        if (!v5)
            return STATUS_INSUFFICIENT_RESOURCES;
        memcpy(v5, InPath, v7);

        *OutPath = v5;
        *PathLength = v7;
    }

    return STATUS_SUCCESS;
}

NTSTATUS TranslateDosToNtInternal(
    const WCHAR* InPath, POOL* Pool, WCHAR** OutPath, ULONG* PathLength)
{
    NTSTATUS Status;
    WCHAR* v5;
    const ULONG v7 = 256;

    *OutPath = NULL;
    *PathLength = 0;

    //
    // handle shares
    //

    Status = TranslateShares(InPath, Pool, OutPath, PathLength);
    if (Status != STATUS_BAD_INITIAL_PC)
        return Status;

    //
    // the input dos path may begin with \??\, which we just ignore
    //

    if (InPath[0] == L'\\' && InPath[1] == L'?' &&
        InPath[2] == L'?' && InPath[3] == L'\\')
    {
        InPath += 4;
    }

    //
    // the input dos path must begin (or continue) with x:\ or
    // x: immediately followed by a null terminator,
    //

    if ((!InPath[0]) || InPath[1] != L':' ||
        (InPath[2] != L'\\' && InPath[2] != L'\0')) {

        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    // we are going to open the symbolic link object \??\x: and query
    // its target path, and do this iteratively as long as the target
    // path is a symbolic link itself.  here we initialize the loop

    v5 = MemoryPoolAllocate(Pool, (v7 + 2) * sizeof(WCHAR));
    if (!v5)
        return STATUS_INSUFFICIENT_RESOURCES;

   v5[0] = L'\\';
   v5[1] = L'?';
   v5[2] = L'?';
   v5[3] = L'\\';
   v5[4] = InPath[0];
   v5[5] = L':';
   v5[6] = L'\0';

    Status = TranslateSymlinks(v5, v7);

    // the loop ends due to error.  if it was STATUS_OBJECT_TYPE_MISMATCH,
    // it means we parsed symbolic links until we reached the actual device
    // object, which we can return.  any other status is an error

    if (NT_SUCCESS(Status)) {

        ULONG NameLength = wcslen(v5);

        WCHAR* v1;
        ULONG v2 = (NameLength + wcslen(&InPath[2]) + 1) * sizeof(WCHAR);
        if (!InPath[2]) {
            // if the dos path was just x:, we'll add one backslash
            v2 += sizeof(WCHAR);
        }
        v1 = MemoryPoolAllocate(Pool, v2);
        if (v1) {

            wmemcpy(v1, v5, NameLength);
            if (!InPath[2])
                wcscpy(v1 + NameLength, L"\\");
            else
                wcscpy(v1 + NameLength, &InPath[2]);

            Status = TranslateShares(v1, Pool, OutPath, PathLength);
            if (Status != STATUS_BAD_INITIAL_PC)
                MemoryPoolFree(v1, v2);
            else {

                *OutPath = v1;
                *PathLength = v2;
                Status = STATUS_SUCCESS;
            }

        }
        else
            Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    MemoryPoolFree(v5, (v7 + 2) * sizeof(WCHAR));
    return Status;
}


NTSTATUS TranslateShares(
    const WCHAR* InPath, POOL* Pool, WCHAR** OutPath, ULONG* PathLength)
{
    WCHAR* v5;
    ULONG PrefixLength;
    ULONG v7;

    //
    // if the path begins with the DOS-style UNC prefix of two backslashes,
    // then replace it with \Device\Mup
    //

    if (InPath[0] == L'\\' && InPath[1] == L'\\' &&
        InPath[2] != L'\0' && InPath[2] != L'\\') {

        v7 = (__MupLength + wcslen(&InPath[1]) + 1) * sizeof(WCHAR);
        v5 = MemoryPoolAllocate(Pool, v7);
        if (!v5)
            return STATUS_INSUFFICIENT_RESOURCES;

        wmemcpy(v5, __Mup, __MupLength);
        wcscpy(v5 + __MupLength, &InPath[1]);

        *OutPath = v5;
        *PathLength = v7;
        return STATUS_SUCCESS;
    }

    //
    // if the path begins with \Device\LanmanRedirector prefix, change
    // to the \Device\Mup prefix
    //

    if (_wcsnicmp(InPath, __Redirector, __RedirectorLength) == 0)
        PrefixLength = __RedirectorLength;
    else if (_wcsnicmp(InPath, __MupRedir, __MupRedirLength) == 0)
        PrefixLength = __MupRedirLength;
    else if (_wcsnicmp(InPath, __DfsClientRedir, __DfsClientRedirLength) == 0)
        PrefixLength = __DfsClientRedirLength;
    else if (_wcsnicmp(InPath, __HgfsRedir, __HgfsRedirLength) == 0)
        PrefixLength = __HgfsRedirLength;
    else
        PrefixLength = 0;

    if (PrefixLength) {

        const WCHAR* v1 = InPath + PrefixLength;
        if (v1[0] == L'\\') {
            //
            // we need to skip a path component, if path has a semicolon:
            // \Device\LanmanRedirector\;Z:0000000000009c2c\server\share
            // otherwise we don't skip at all, as in such a path:
            // \Device\LanmanRedirector\server\share
            //
            if (v1[1] == L';')
                v1 = wcschr(v1 + 2, L'\\');
        }
        else
            v1 = NULL;
        if (v1 && v1[0] && v1[1]) {

            v7 = (PrefixLength + wcslen(v1) + 1) * sizeof(WCHAR);
            v5 = MemoryPoolAllocate(Pool, v7);
            if (!v5)
                return STATUS_INSUFFICIENT_RESOURCES;

            wmemcpy(v5, __Mup, __MupLength);
            wcscpy(v5 + __MupLength, v1);

            *OutPath = v5;
            *PathLength = v7;
            return STATUS_SUCCESS;
        }
    }

    //
    // otherwise, return special value to indicate no share name translation
    //

    return STATUS_BAD_INITIAL_PC;
}

NTSTATUS TranslateSymlinks(WCHAR* BufferData, ULONG DataLength)
{
    NTSTATUS Status;
    HANDLE Handle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING UnicodeString;
    ULONG v7, v2, Offset;
    ULONG Retry = 0;
    BOOLEAN IsFound = FALSE;

    //DbgPrint("-------------------------------------------\n");

    InitializeObjectAttributes(&ObjectAttributes,
        &UnicodeString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    UnicodeString.Buffer = BufferData;

    v7 = wcslen(BufferData);

    Retry = 0;

Top:

    ++Retry;
    if (Retry == 8)
        return STATUS_REPARSE_POINT_NOT_RESOLVED;

    //DbgPrint("[Retry %d] Path <%S>\n", retry, name);

    //
    // try to open the longest symbolic link we find.  for instance,
    // if the object name is \??\PIPE\MyPipe, we will open the link
    // "\??\PIPE" even though "\??\" itself is also a link
    //

    while (1) {

        WCHAR v1 = BufferData[v7];
        BufferData[v7] = L'\0';

        if (v7 == 7 && _wcsicmp(BufferData, L"\\Device") == 0) {

            Status = STATUS_OBJECT_TYPE_MISMATCH;

            //DbgPrint("[Retry %d] Fake Status <%08X> for Open <%S>\n", retry, status, BufferData);

        }
        else {

            UnicodeString.Length = (USHORT)(v7 * sizeof(WCHAR));
            UnicodeString.MaximumLength = (USHORT)(UnicodeString.Length + sizeof(WCHAR));

            Status = ZwOpenSymbolicLinkObject(
                &Handle, SYMBOLIC_LINK_QUERY, &ObjectAttributes);

            //DbgPrint("[Retry %d] Status <%08X> for Open <%S>\n", retry, status, BufferData);
        }

        BufferData[v7] = v1;

        if (NT_SUCCESS(Status))
            break;

        Handle = NULL;

        if (v7 <= 1)
            break;

        do {
            --v7;
        } while (v7 && BufferData[v7] != L'\\');

        if (v7 <= 1)
            break;
    }

    //
    // if we couldn't locate a symbolic link then we're done
    //

    if (!Handle) {

        if (Status == STATUS_OBJECT_TYPE_MISMATCH) {

            if (IsFound)
                Status = STATUS_SUCCESS;
            else
                Status = STATUS_OBJECT_PATH_SYNTAX_BAD;

        }
        else if (Status == STATUS_OBJECT_NAME_NOT_FOUND ||
            Status == STATUS_OBJECT_PATH_NOT_FOUND)
            Status = STATUS_OBJECT_PATH_SYNTAX_BAD;

        //DbgPrint("[Retry %d] Exit1 with Status <%08X>\n", retry, status);

        return Status;
    }

    IsFound = TRUE;

    //
    // move the suffix beyond the symbolic link prefix to the
    // end of the buffer, and then query the symbolic link into
    // the start of the buffer
    //

    v2 = wcslen(BufferData) - v7;
    Offset = DataLength - v2;
    //DbgPrint("[Retry %d] OldLen=%d Rem=%d Ofs=%d\n", retry, v7, v2, ofs);
    if (v2)
        wmemmove(BufferData + Offset, BufferData + v7, v2);

    UnicodeString.Length = (USHORT)((Offset - 1) * sizeof(WCHAR));
    UnicodeString.MaximumLength = (USHORT)(UnicodeString.Length + sizeof(WCHAR));

    Status = ZwQuerySymbolicLinkObject(Handle, &UnicodeString, NULL);

    ZwClose(Handle);

    if (!NT_SUCCESS(Status)) {
        //DbgPrint("[Retry %d] Exit2 with Status <%08X>\n", retry, status);
        return Status;
    }

    v7 = UnicodeString.Length / sizeof(WCHAR);
    //DbgPrint("[Retry %d] NewLen=%d\n", retry, v7);
    if (v2) {
        wmemmove(BufferData + v7, BufferData + Offset, v2);
        v7 += v2;
    }
    BufferData[v7] = L'\0';

    goto Top;
}