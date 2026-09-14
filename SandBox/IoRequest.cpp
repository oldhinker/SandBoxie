#include "IoRequest.h"
#include "ApiHelper.h"
#include "ObjectHelper.h"
#include "StatusHelper.h"
#include <ntstatus.h>
#include "FileHelper.h"
#include "_tWinMain.h"




HANDLE __DeviceHandle = INVALID_HANDLE_VALUE;



LPFN_NTCREATEPORT __NtCreatePort = NULL;
LPFN_NTREPLYWAITRECEIVEPORT __NtReplyWaitReceivePort = NULL;
LPFN_LPCREQUESTPORT         __LpcRequestPort = NULL;




bool InitializeIoDevice()
{
    if (__Ntdll == NULL)
    {
        __Ntdll = GetModuleHandle(_T("ntdll.dll"));
    }
    __NtCreatePort = (LPFN_NTCREATEPORT)GetProcAddress(__Ntdll, "NtCreatePort");

    __NtReplyWaitReceivePort = (LPFN_NTREPLYWAITRECEIVEPORT)GetProcAddress(__Ntdll, "NtReplyWaitReceivePort");


    __LpcRequestPort = (LPFN_LPCREQUESTPORT)GetProcAddress(__Ntdll, "LpcRequestPort");

    if (!__NtCreatePort || !__NtReplyWaitReceivePort
        || !__LpcRequestPort)
        return false;
}


LONG IoctlRequest(ULONG ServiceIndex, LONG ParameterCounts, ...)
{
    va_list  v1;
    NTSTATUS Status;
    __declspec(align(8)) ULONG64 ParameterData[API_NUMBER_ARGS];

    ZeroMemory(ParameterData, sizeof(ParameterData));
    ParameterData[0] = ServiceIndex;

    if (ParameterCounts >= (API_NUMBER_ARGS - 1))
        return STATUS_INVALID_PARAMETER;

    va_start(v1, ParameterCounts);
    for (LONG i = 1; i <= ParameterCounts; i++)
        ParameterData[i] = (ULONG64)va_arg(v1, ULONG_PTR);
    va_end(v1);

    Status = IoctlRequestInternal(ParameterData);

    return Status;
}

//打开Ring0设备
NTSTATUS IoctlRequestInternal(ULONG64* ParameterData)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING v1;
    IO_STATUS_BLOCK IoStatusBlock;

    if (ParameterData == NULL)
    { // close request as used by kmdutil
        if (__DeviceHandle != INVALID_HANDLE_VALUE)
            __NtClose(__DeviceHandle);
        __DeviceHandle = INVALID_HANDLE_VALUE;
    }

     

    if (__DeviceHandle == INVALID_HANDLE_VALUE) {


        //通过设备对象名获取设备对象句柄 
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

        if (0)
        {
               
        }
        else 
        {

            Status = __NtDeviceIoControlFile(
                __DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                IO_CTL_CODE_1, ParameterData, sizeof(ULONG64) * 8, NULL, 0);
        }

    }

    return Status;
}


