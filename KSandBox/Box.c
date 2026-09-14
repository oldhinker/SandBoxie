#include "Box.h"
#include "MemoryHelper.h"


BOX* CreateBox(
    POOL* Pool, const WCHAR* BoxName,
    const WCHAR* SidString, ULONG SessionIdentity,
    BOOLEAN IsInitializePaths)
{
    BOX* Box;

    Box = CreateBoxInternal(Pool, BoxName, SessionIdentity);
    if (!Box)
        return NULL;


    return Box;
}

BOX* CreateBoxInternal(POOL* Pool, const WCHAR* BoxName, ULONG SessionIdentity)
{
    BOX* Box = MemoryPoolAllocate(Pool, sizeof(BOX));
    if (!Box) {

     
        return NULL;
    }

    MemoryZero(Box, sizeof(BOX));

    wcscpy(Box->BoxName, BoxName);
    Box->NameLength = (wcslen(Box->BoxName) + 1) * sizeof(WCHAR);

    return Box;
}



BOX* CloneBox(POOL* Pool, const BOX* Box)
{
    BOX* v5;

    v5 = AllocateBox(Pool, Box->BoxName, Box->SessionIdentity);
    if (!v5)
        return NULL;



    return v5;
}


BOX* AllocateBox(POOL* Pool, const WCHAR* BoxName, ULONG SessionIdentity)
{
    static const WCHAR* _IpcRootPath_Default =
        L"\\Sandbox";
   
    BOX* Box = MemoryPoolAllocate(Pool, sizeof(BOX));
    if (!Box) {

   
        return NULL;
    }

    MemoryZero(Box, sizeof(BOX));

    wcscpy(Box->BoxName, BoxName);
    Box->NameLength = (wcslen(Box->BoxName) + 1) * sizeof(WCHAR);



    //²âÊÔ
    Box->IpcPath = MemoryPoolAllocate(Pool, sizeof(_IpcRootPath_Default));
    wcscpy(Box->IpcPath, _IpcRootPath_Default);
    Box->IpcLength = (wcslen(Box->IpcPath) + 1) * sizeof(WCHAR);


    return Box;
}


void FreeBox(BOX* Box)
{
    if (Box) {
        /*
        if (box->sid)
            Mem_Free(box->sid, box->sid_len);
        if (box->expand_args)
            Mem_Free(box->expand_args, sizeof(CONF_EXPAND_ARGS));
        if (box->file_path)
            Mem_Free(box->file_path, box->file_path_len);
        if (box->file_raw_path)
            Mem_Free(box->file_raw_path, box->file_raw_path_len);
        if (box->key_path)
            Mem_Free(box->key_path, box->key_path_len);*/
        if (Box->IpcPath)
            FreeMemoryEx(Box->IpcPath, Box->IpcLength);
        /*
        if (box->pipe_path)
            Mem_Free(box->pipe_path, box->pipe_path_len);
        if (box->system_temp_path)
            Mem_Free(box->system_temp_path, box->system_temp_path_len);
        if (box->user_temp_path)
            Mem_Free(box->user_temp_path, box->user_temp_path_len);
        if (box->spooler_directory)
            Mem_Free(box->spooler_directory, box->spooler_directory_len);*/
        FreeMemoryEx(Box, sizeof(BOX));
    }
}



NTSTATUS CopyBoxPathsToUser(
    BOX* Box, ULONG* FileLength, ULONG* KeyLength, ULONG* IpcLength,
    UNICODE_STRING64* FilePath,
    UNICODE_STRING64* KeyPath,
    UNICODE_STRING64* IpcPath)
{
    NTSTATUS Status;

    __try {

        //
        // store the result lengths, if parameters were given
        //

        /*
        if (file_path_len) {
            ProbeForWrite(file_path_len, sizeof(ULONG), sizeof(ULONG));
            *file_path_len = box->file_path_len;
        }

        if (key_path_len) {
            ProbeForWrite(key_path_len, sizeof(ULONG), sizeof(ULONG));
            *key_path_len = box->key_path_len;
        }*/

        if (IpcLength) {
            ProbeForWrite(IpcLength, sizeof(ULONG), sizeof(ULONG));
            *IpcLength = Box->IpcLength;
        }

        //
        // copy the strings, if specified
        //

        //CopyStringToUser(file_path, box->file_path, box->file_path_len);
        //CopyStringToUser(key_path, box->key_path, box->key_path_len);
        CopyStringToUser(IpcPath, Box->IpcPath, Box->IpcLength);

        Status = STATUS_SUCCESS;

        //
        // finish
        //

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    return Status;
}


