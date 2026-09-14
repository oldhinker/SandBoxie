#include "IpcHelper.h"
#include "ApiHelper.h"
BOOLEAN InitializeIpc(void)
{


	SetCommonService(CREATE_DIR_OR_LINK, CreateDirOrLink);

}


BOOLEAN CreateBoxIpcPath(PROCESS* Process)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING ObjectName;
    ULONG Retries;
    HANDLE DirectoryHandle = NULL;
    NTSTATUS Status;
    WCHAR* v1 = NULL;
    Retries = 0;


    //对象安全属性的配置


    InitializeObjectAttributes(
        &ObjectAttributes, &ObjectName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, // | OBJ_PERMANENT,
        NULL, NULL);
    while (Retries < 64) {

        ++Retries;
        RtlInitUnicodeString(&ObjectName, Process->Box->IpcPath);

        Status = ZwCreateDirectoryObject(
            &DirectoryHandle, DIRECTORY_ALL_ACCESS, &ObjectAttributes);

        if (Status == STATUS_OBJECT_PATH_NOT_FOUND) {

            //
            // if parent directories are missing, terminate the
            // path at the last backslash and retry the loop
            //

            WCHAR* v2 = wcsrchr(Process->Box->IpcPath, L'\\');
            if (v1)
                *v1 = L'\\';
            v1 = v2;
            if (v1)
                *v1 = L'\0';

        }
        else {

            //
            // if we could create the path, we check if any backslashes
            // were zeroed out.  if so, we restart the loop from the top
            // using the full path.  otherwise, we're done
            //

            if (NT_SUCCESS(Status)) {

                //ZwClose(handle);

                /* 数据结构保存
                KIRQL irql;
                KeRaiseIrql(APC_LEVEL, &irql);
                ExAcquireResourceExclusiveLite(Ipc_DirLock, TRUE);

                DIR_OBJ_HANDLE* obj_handle = Mem_Alloc(Driver_Pool, sizeof(DIR_OBJ_HANDLE));
                obj_handle->handle = handle;
                List_Insert_After(&Ipc_ObjDirs, NULL, obj_handle);

                ExReleaseResourceLite(Ipc_DirLock);
                KeLowerIrql(irql);*/
            }

            if (Status == STATUS_OBJECT_NAME_COLLISION)
                Status = STATUS_SUCCESS;

            if (v1) {

                *v1 = L'\\';
                v1 = NULL;

            }
            else
                break;
        }
    }

    if (Retries >= 64)
        Status = STATUS_UNSUCCESSFUL;

    if (!NT_SUCCESS(Status)) {

        //日志记录
    }

    return (NT_SUCCESS(Status));
}