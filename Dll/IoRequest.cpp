#include "IoRequest.h"
#include "ApiHelper.h"
#include "ObjectHelper.h"
#include "StatusHelper.h"
#include "ExportServices.h"
#include "FileHelper.h"
#include "dllmain.h"
#include "StringHelper.h"



LPFN_NTDEVICEIOCONTROLFILE      __sys_NtDeviceIoControlFile = NULL;


LONG IoctlRequest(ULONG64* ParameterData)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING v1;
    IO_STATUS_BLOCK IoStatusBlock;

    if (ParameterData == NULL) { // close request as used by kmdutil
        if (__DeviceHandle != INVALID_HANDLE_VALUE)
            __NtClose(__DeviceHandle);
        __DeviceHandle = INVALID_HANDLE_VALUE;
    }
    if (__DeviceHandle == INVALID_HANDLE_VALUE) {

        RtlInitUnicodeString(&v1, DEVICE_NAME);
        InitializeObjectAttributes(
            &ObjectAttributes, &v1, OBJ_CASE_INSENSITIVE, NULL, NULL);

        Status = __NtOpenFile(
            &__DeviceHandle, FILE_GENERIC_READ, &ObjectAttributes,
            &IoStatusBlock,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0);

        if (Status == STATUS_OBJECT_NAME_NOT_FOUND ||
            Status == STATUS_NO_SUCH_DEVICE)
            Status = STATUS_SERVER_DISABLED;

    }
    else
        Status = STATUS_SUCCESS;

    if (Status != STATUS_SUCCESS) {

        __DeviceHandle = INVALID_HANDLE_VALUE;

    }
    else
    {

   
        if (__sys_NtDeviceIoControlFile)
        {

        //
        // once NtDeviceIoControlFile is hooked, bypass it
        //

            Status = __sys_NtDeviceIoControlFile(
                __DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                IO_CTL_CODE_1, ParameterData, sizeof(ULONG64) * 8, NULL, 0);

        }
        else {

            Status = __NtDeviceIoControlFile(
                __DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                IO_CTL_CODE_1, ParameterData, sizeof(ULONG64) * 8, NULL, 0);
        }

    }

    return Status;
}
