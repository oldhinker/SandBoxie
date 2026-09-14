#include "IoRequest.h"
#include "ApiHelper.h"
#include "MemoryHelper.h"
#include "MemoryLock.h"


FAST_IO_DISPATCH* __FastIoDispatch = NULL;



BOOLEAN FastIoDeviceControl(
    FILE_OBJECT* FileObject, BOOLEAN Wait,
    void* InputBuffer, ULONG InputBufferLength,
    void* OutputBuffer, ULONG OutputBufferLength,
    ULONG IoControlCode, IO_STATUS_BLOCK* IoStatus,
    DEVICE_OBJECT* DeviceObject)
{
    NTSTATUS Status;
 

    ULONG v7, ServiceIndex;
    ULONG64* v5;
    ULONG64  BufferData[API_NUMBER_ARGS] = { 0 };
    PROCESS* Process = NULL;   //自定义结构
    LPFN_FUNCTION v1;
#ifdef _DEBUG
    BOOLEAN ApcsDisabled;
#endif

    //
    // SeFilterToken in kernel mode
    //

    if (0)
    {
      
        return TRUE;
    }
    else if (0)
    {
    
        return TRUE;
    }


    //
    // we only handle direct invocations by user-mode callers at low irql
    //

    IoStatus->Information = 0;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL
        || ExGetPreviousMode() != UserMode) {

        IoStatus->Status = STATUS_INVALID_LEVEL;
        return TRUE;
    }

    //
    // get pointer to user buffer and length
    //

    v5 = NULL;

    if (IoControlCode == IO_CTL_CODE_1) 
    {

        v7 = InputBufferLength;
        if (v7 >= sizeof(ULONG64)
            && v7 <= sizeof(ULONG64) * API_NUMBER_ARGS)
            v5 = InputBuffer;
    }

    if (!v5) {

        IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;   //Ring3的返回
        return TRUE;
    }

    //
    // find calling process
    //

#ifdef _DEBUG
    ApcsDisabled = KeAreApcsDisabled();
#endif


  
    if (PsGetCurrentProcessId() == __ProcessIdentity)   //
        Process = NULL;
    else {

        Process = FindProcess(NULL, NULL);
        if (Process == PROCESS_TERMINATED) 
        {

            IoStatus->Status = STATUS_PROCESS_IS_TERMINATING;
            return TRUE;
        }
    }


    //
    // capture parameter and call function
    //

    ServiceIndex = 0;
    v1 = NULL;

    __try {

        ProbeForRead(
            v5, sizeof(ULONG64) * API_NUMBER_ARGS, sizeof(ULONG64));

        MemoryZero(BufferData, sizeof(ULONG64) * API_NUMBER_ARGS);
        memcpy(BufferData, v5, v7);

        ServiceIndex = (ULONG)BufferData[0];

        if (ServiceIndex > FIRST_1 && ServiceIndex < LAST_1)
            v1 = __CommonServices[ServiceIndex - FIRST_1 - 1];

        if (v1) {

            Status = v1(Process, BufferData);

            

        }
        else
            Status = STATUS_INVALID_DEVICE_REQUEST;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    //
    // make sure IRQL and APCs were restored correctly
    //

#ifdef _DEBUG
    if (KeGetCurrentIrql() != PASSIVE_LEVEL
        || (KeAreApcsDisabled() ^ ApcsDisabled)) {

        KeBugCheckEx(DRIVER_CORRUPTED_MMPOOL,
            tzuk, KeGetCurrentIrql(), 0x123400, func_code);
    }
#endif

    IoStatus->Status = Status;
    return TRUE;
}
BOOLEAN SendLpcMessage(ULONG Protocol, ULONG DataLength, void* MessageData)
{

    UCHAR v5[MAX_MESSAGE_LENGTH];
    PORT_MESSAGE* PortMessage = (PORT_MESSAGE*)v5;
    void* PortObject;
    KIRQL Irql;
    BOOLEAN IsOk;

    //
    // abort if we know in advance that we won't have a service port
    //


    //自己的Ring3进程
    if (!__ProcessIdentity)
        return FALSE;

    //
    // prepare the request message structure.  the data area of the message
    // follows the PORT_MESSAGE header.  the first ULONG is the msgid field,
    // followed by the rest of the caller data
    //

    if (DataLength > DATA_LENGTH)
        return FALSE;

    MemoryZero(PortMessage, sizeof(PORT_MESSAGE));
    PortMessage->u1.s1.DataLength = (USHORT)(DataLength + sizeof(ULONG));
    PortMessage->u1.s1.TotalLength = PortMessage->u1.s1.DataLength + sizeof(PORT_MESSAGE);
    PortMessage->u2.s2.Type = LPC_DATAGRAM;

    *(ULONG*)(v5 + sizeof(PORT_MESSAGE)) = Protocol;
    memcpy(v5 + sizeof(PORT_MESSAGE) + sizeof(ULONG), MessageData, DataLength);

    //
    // send the message to SbieSvc on the LPC port
    //


    EnterResourceLock(__CommonResourceLock, &Irql);

    PortObject = __PortObject;        
      
    if (PortObject)
        ObReferenceObject(PortObject);

    LeaveResourceLock(__CommonResourceLock, Irql);

    if (PortObject)
    {

        // port must have a name, or LpcRequestPort will fail
        // see also core/svc/driverassist.cpp
        NTSTATUS status = LpcRequestPort(PortObject, PortMessage);

        ObDereferenceObject(PortObject);

        if (NT_SUCCESS(status))
            IsOk = TRUE;
        else
            IsOk = FALSE;

    }
    else
        IsOk = FALSE;

    return IsOk;
}

NTSTATUS IrpCreateDispatch(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
    NTSTATUS Status = STATUS_SUCCESS;


    return Status;
}
NTSTATUS IrpCleanUpDispatch(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
    NTSTATUS Status = STATUS_SUCCESS;


    return Status;
}