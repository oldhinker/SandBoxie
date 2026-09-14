#include "Common.h"
#include "ApiHelper.h"
#include "MemoryLock.h"
#include "DriverEntry.h"
#include "MemoryHelper.h"
#include "SystemHelper.h"
#include "ObjectHelper.h"
#include "IoRequest.h"
#include "Syscall.h"
#include "ProcessHelper.h"



PERESOURCE __CommonResourceLock = NULL;
static PBOOLEAN   _IsCommonResourceLock = FALSE;
static PDEVICE_OBJECT _DeviceObject = NULL; //Ring0 <--> Ring3 设备对象(Irp FastIo)  
volatile HANDLE __ProcessIdentity = NULL;    //Ring0的Ring3
void* __PortObject = NULL;            //Ring0 <--> Ring3 端口对象(端口通信)
static volatile LONG _UseCount = -1;


LPFN_COMMONSERVICE* __CommonServices = NULL; //是一个二维指针动态存储一个连续内存的函数指针的数组
BOOLEAN InitializeCommonData(void)
{
    NTSTATUS Status;
    UNICODE_STRING v1;

    //
    // initialize log buffer
    //


    //
    // initialize lock
    //

    if (!GetResourceLock(&__CommonResourceLock, TRUE))
        return FALSE;

    _IsCommonResourceLock = TRUE;

    //
    // initialize Fast IO dispatch pointers
    //


    //FastIo Irp Ring3与Ring0通信方法

    //初始化FastIo






    //
    // initialize IRP dispatch pointers
    //


    //Irp派遣


   

    //创建设备对象
    RtlInitUnicodeString(&v1, DEVICE_NAME);
    Status = IoCreateDevice(
        __DriverObject, 0, &v1,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
        &_DeviceObject);

    if (!NT_SUCCESS(Status)) {
        _DeviceObject = NULL;
   
        return FALSE;
    }

    _DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    //
    // set API functions
    //

    //IoCtrlCode Ring3<-->Ring0
    __FastIoDispatch = ExAllocatePoolWithTag(NonPagedPool, sizeof(FAST_IO_DISPATCH), TAG);
    if (!__FastIoDispatch) {
      
        return FALSE;
    }

    MemoryZero(__FastIoDispatch, sizeof(FAST_IO_DISPATCH));
    __FastIoDispatch->SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);
    __FastIoDispatch->FastIoDeviceControl = FastIoDeviceControl;   //派遣函数

    __DriverObject->FastIoDispatch = __FastIoDispatch;




    __DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateDispatch;
    __DriverObject->MajorFunction[IRP_MJ_CLEANUP] = IrpCleanUpDispatch;




    //保存重要数据
    SetCommonService(GET_DRIVER_VERSION, GetDriverVersion);
   
    SetCommonService(SET_SERVICE_PORT, SetServicePort);
    SetCommonService(GET_HOME_PATH, GetHomePath);


    SetCommonService(QUERY_DRIVER_INFO, QueryDriverInfo);

    if ((!__CommonServices) || (__CommonServices == (void*)-1))
        return FALSE;

    //
    // indicate API is ready for use
    //

    InterlockedExchange(&_UseCount, 0);

    return TRUE;
}
BOOLEAN UninitializeCommonData(void)
{
    if (_DeviceObject) {
        IoDeleteDevice(_DeviceObject);
        _DeviceObject = NULL;
    }

    if (__FastIoDispatch) {
        ExFreePoolWithTag(__FastIoDispatch, TAG);
        __FastIoDispatch = NULL;
    }
    if (_IsCommonResourceLock) {

        FreeResourceLock(&__CommonResourceLock);

        _IsCommonResourceLock = FALSE;
    }

    if (__PortObject) {
        ObDereferenceObject(__PortObject);
        __PortObject = NULL;
    }

    if (__CommonServices)
    {
        ULONG v7 = (LAST_1 - FIRST_1 - 1) * sizeof(LPFN_COMMONSERVICE);
        FreeMemoryEx(__CommonServices, v7);
    }
}
void SetCommonService(ULONG ServiceIndex, LPFN_COMMONSERVICE CommonService)
{
    if (!__CommonServices) 
    {

        ULONG v7 = (LAST_1 - FIRST_1 - 1) * sizeof(LPFN_COMMONSERVICE);
        __CommonServices = AllocateMemoryEx(__Pool, v7, TRUE);

        if (__CommonServices)
            MemoryZero(__CommonServices, v7);
        else
            __CommonServices = (void*)-1;
    }

    if ((__CommonServices != (void*)-1) &&
        (ServiceIndex > FIRST_1) && (ServiceIndex < LAST_1)) {

        __CommonServices[ServiceIndex - FIRST_1 - 1] = CommonService;
    }
}

NTSTATUS GetDriverVersion(PPROCESS Process, ULONG64* ParameterData)
{
    GET_DRIVER_VERSION_ARGS* Arguments = (GET_DRIVER_VERSION_ARGS*)ParameterData;

    if (Arguments->DriverVersion1.Value != NULL)
    {
        size_t v7 = (wcslen(__DriverVersion) + 1) * sizeof(WCHAR);
        ProbeForWrite(Arguments->DriverVersion1.Value, v7, sizeof(WCHAR));
        memcpy(Arguments->DriverVersion1.Value, __DriverVersion, v7);
    }

    if (Arguments->DriverVersion2.Value != NULL) {
        ProbeForWrite(Arguments->DriverVersion2.Value, sizeof(ULONG), sizeof(ULONG));
        *Arguments->DriverVersion2.Value = DRIVER_VERSION;
    }

    return STATUS_SUCCESS;
}

NTSTATUS SetServicePort(PPROCESS Process, ULONG64* ParameterData)
{
    //
    // confirm the caller is an unsandboxed system process in
    // our installation folder, i.e. the Sandboxie service
    //

    NTSTATUS Status = STATUS_ACCESS_DENIED;

    if (1)
    {

        Status = STATUS_SUCCESS;
    }

    if (0)
    {

        Status = STATUS_INVALID_SIGNATURE;
    }

    //
    // take a reference on the specified LPC port object
    //

    if (NT_SUCCESS(Status)) {

        void* PortObject, * OldObject;

        HANDLE PortHandle = (HANDLE)(ULONG_PTR)ParameterData[1];   //Ring3创建的端口句柄
        if (PortHandle) {

            //通过句柄获取对象
            Status = ObReferenceObjectByHandle(
                PortHandle, 0, *LpcPortObjectType, KernelMode,
                &PortObject, NULL);
        }
        else {

            PortObject = NULL;
            Status = STATUS_SUCCESS;
        }

        //
        // replace the stored port object reference,
        // release the reference on the old stored port object
        //

        if (NT_SUCCESS(Status)) {


            KIRQL Irql;
            EnterResourceLock(__CommonResourceLock, &Irql);



            //保存对象到全局变量中
            OldObject = InterlockedExchangePointer(
                &__PortObject, PortObject);

            InterlockedExchangePointer(
                &__ProcessIdentity, PsGetCurrentProcessId());

            LeaveResourceLock(__CommonResourceLock, Irql);

            if (OldObject)
                ObDereferenceObject(OldObject);
        }
    }

    return Status;
}
void ResetServicePort(void)
{
    if (__PortObject) {

        KIRQL Irql;
        EnterResourceLock(__CommonResourceLock, &Irql);

        void* v1 = InterlockedExchangePointer(&__PortObject, NULL);

        ObDereferenceObject(v1);

        LeaveResourceLock(__CommonResourceLock, Irql);
    }

    InterlockedExchangePointer(&__ProcessIdentity, NULL);
}
NTSTATUS GetHomePath(PROCESS* Process, ULONG64* ParameterData)
{
    GET_HOME_PATH_ARGS* Arguments = (GET_HOME_PATH_ARGS*)ParameterData;
    UNICODE_STRING64* PathData;
    WCHAR* v5;
    size_t v7;

    PathData = Arguments->NtPath.Value;
    if (PathData) {
        v5 = __HomePath1;
        v7 = (wcslen(v5) + 1) * sizeof(WCHAR);
        CopyStringToUser(PathData, v5, v7);
    }

    PathData = Arguments->DosPath.Value;
    if (PathData) {
        v5 = __HomePath2;
        if (wcsncmp(v5, L"\\??\\", 4) == 0)
            v5 += 4;
        v7 = (wcslen(v5) + 1) * sizeof(WCHAR);
        CopyStringToUser(PathData, v5, v7);
    }

    return STATUS_SUCCESS;
}
NTSTATUS QuerySyscalls(PROCESS* Process, ULONG64* ParameterData)
{
    ULONG v7;
    ULONG* v5;
    ULONG* v1;
    SYSCALL_ENTRY* SyscallEntry;

#ifdef HOOK_WIN32K
    if (ParameterData[2] == 1) { // 1 - win32k
        return Syscall_Api_Query32(proc, parms);
    }
    else if (ParameterData[2] != 0) { // 0 - ntoskrnl
        return STATUS_INVALID_PARAMETER;
    }
#endif

    BOOLEAN IsServiceName = ParameterData[3] != 0;

    //
    // caller must be our service process
    //

    if (Process || (PsGetCurrentProcessId() != __ProcessIdentity))
        return STATUS_ACCESS_DENIED;

    //
    // allocate user mode space for syscall table
    //

    v7 = sizeof(ULONG)         // size of buffer
        + sizeof(ULONG)         // offset to extra data (for SbieSvc)
        + (NATIVE_FUNCTION_SIZE * NATIVE_FUNCTION_COUNT) // saved code from ntdll
        + GetListCount(&__SyscallsList) * ((sizeof(ULONG) * 2) + (IsServiceName ? 64 : 0))
        + sizeof(ULONG) * 2     // final terminator entry
        ;

    v5 = (ULONG*)ParameterData[1];

    ProbeForWrite(v5, v7, sizeof(ULONG));

    //
    // populate the buffer with syscall data.  first we store
    // the size of the buffer, and then we leave room for ULONG used
    // by SbieSvc, and for the code for four ZwXxx stub functions
    //

    v1 = v5;
    *v1 = v7;
    ++v1;

    *v1 = 0;           // placeholder for offset to extra offset
    ++v1;


    memcpy(v1, __SyscallsCode, (NATIVE_FUNCTION_SIZE * NATIVE_FUNCTION_COUNT));
    v1 += (NATIVE_FUNCTION_SIZE * NATIVE_FUNCTION_COUNT) / sizeof(ULONG);


    //
    // store service index number and (only on 32-bit Windows) also
    // the parameter count for each syscall into one ULONG.
    // store corresponding offset within ntdll into the other ULONG
    //

    for (SyscallEntry = GetListHead(&__SyscallsList); SyscallEntry; SyscallEntry = GetNextNode(SyscallEntry))
    {

        if (SyscallEntry->disabled)
            continue;

        ULONG ServiceIndex = (ULONG)SyscallEntry->ServiceIndex;
      
#ifndef _WIN64
        ULONG ParameterCount = (ULONG)SyscallEntry->ParameterCount;
        ServiceIndex |= (ParameterCount * 4) << 24;
#endif ! _WIN64

        *v1 = ServiceIndex;
        ++v1;
        *v1 = SyscallEntry->ServiceOffset;
        ++v1;
        if (IsServiceName)
        {
            memcpy(v1, SyscallEntry->ServiceName, SyscallEntry->NameLength);
            ((char*)v1)[SyscallEntry->NameLength] = 0;
            v1 += 16; // 16 * sizeog(ULONG) = 64
        }
    }

    //
    // store a final zero terminator entry and return successfully
    //

    *v1 = 0;
    ++v1;
    *v1 = 0;

    return STATUS_SUCCESS;
}

NTSTATUS QueryProcess(PROCESS* Process, ULONG64* ParameterData)
{
    QUERY_PROCESS_ARGS* Arguments = (QUERY_PROCESS_ARGS*)ParameterData;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE ProcessIdentity;
    ULONG* num32;
    ULONG64* num64;
    KIRQL Irql;

    //
    // this is the first SbieApi call by SbieDll
    //


    //让驱动通知目标进程DLL已经被注入了
    if (Process && !Process->IsDllLoaded)
    {
        Process->IsDllLoaded = TRUE;
     
    }

    if (0) {

       
    }

    ProcessIdentity = Arguments->ProcessIdentity.Value;
    if (Process)
    {
        if (ProcessIdentity == Process->ProcessIdentity || IS_ARG_CURRENT_PROCESS(ProcessIdentity))
            ProcessIdentity = 0;  // don't have to search for the current pid
    }
    else {
        if ((!ProcessIdentity) || IS_ARG_CURRENT_PROCESS(ProcessIdentity))
            return STATUS_INVALID_CID;
    }
    if (ProcessIdentity) 
    {

        Process = FindProcess(ProcessIdentity, &Irql);
        if (!Process || Process->IsTerminated) {
            ExReleaseResourceLite(__ProcessListLock);
            KeLowerIrql(Irql);
            return STATUS_INVALID_CID;
        }
    }
    Status = STATUS_SUCCESS;


    __try {


        //拷贝驱动内存到Ring3



    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    if (ProcessIdentity) {

        ExReleaseResourceLite(__ProcessListLock);
        KeLowerIrql(Irql);
    }
    return Status;
}
NTSTATUS QueryDriverInfo(PROCESS* Process, ULONG64* ParameterData)
{
    NTSTATUS Status = STATUS_SUCCESS;
    QUERY_DRIVER_INFO_ARGS* Arguments = (QUERY_DRIVER_INFO_ARGS*)ParameterData;

    __try {

        if (Arguments->InfoClass.Value == 0)
        {

            ULONG* BufferData = Arguments->BufferData.Value;
            ProbeForWrite(BufferData, sizeof(ULONG), sizeof(ULONG));

            ULONG FeatureFlags = 0;






        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    return Status;
}
NTSTATUS QueryProcessInfo(PROCESS* Process, ULONG64* ParameterData)
{
    QUERY_PROCESS_INFO_ARGS* Arguments = (QUERY_PROCESS_INFO_ARGS*)ParameterData;
    NTSTATUS Status;
    HANDLE ProcessIdentity;
    KIRQL Irql;
    BOOLEAN IsCallerSandboxed = FALSE;

    //
    // if a ProcessId was specified, then locate and lock the matching
    // process. ProcessId must be specified if the caller is not sandboxed
    //

    ProcessIdentity = Arguments->ProcessIdentity.Value;
    if (Process) {
        IsCallerSandboxed = TRUE;
        if (ProcessIdentity == Process->ProcessIdentity || IS_ARG_CURRENT_PROCESS(ProcessIdentity))
            ProcessIdentity = 0;  // don't have to search for the current pid
    }
    else {
        if ((!ProcessIdentity) || IS_ARG_CURRENT_PROCESS(ProcessIdentity))
            return STATUS_INVALID_CID;
    }
    if (ProcessIdentity) {

        Process = FindProcess(ProcessIdentity, &Irql);
        if (!Process || Process->IsTerminated) {
            ExReleaseResourceLite(__ProcessListLock);
            KeLowerIrql(Irql);
            return STATUS_INVALID_CID;
        }
    }

    // the rest of the code now has to be protected, because we may
    // have a lock on the Process_List, that we must release

    Status = STATUS_SUCCESS;

    __try {

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    if (ProcessIdentity) {

        ExReleaseResourceLite(__ProcessListLock);
        KeLowerIrql(Irql);
    }

    return Status;
}
NTSTATUS QueryBoxPath(PROCESS* Process, ULONG64* ParameterData)
{
    API_QUERY_BOX_PATH_ARGS* Arguments = (API_QUERY_BOX_PATH_ARGS*)ParameterData;
    BOX* Box = NULL;
    BOOLEAN IsFreeBox;
    NTSTATUS Status;

    //
    // if this API is invoked by a sandboxed process, use its box.
    // otherwise, construct a box according to specified box name
    //

    if (Process) {

        Box = Process->Box;
        IsFreeBox = FALSE;

    }
    else {

      
    }

    Status = CopyBoxPathsToUser(
        Box,
        Arguments->FileLength.Value,
        Arguments->KeyLength.Value,
        Arguments->IpcLength.Value,
        Arguments->FilePath.Value,
        Arguments->KeyPath.Value,
        Arguments->IpcPath.Value);

    if (IsFreeBox)
        FreeBox(Box);

    return Status;
}


NTSTATUS EnumProcessEx(PROCESS* Process, ULONG64* ParameterData)
{
    NTSTATUS Status;
    BOOLEAN IsAllSessions;
    ULONG SessionIdentity;
    ULONG* ProcessIdentitys;
    ULONG* Count;
    WCHAR v1[BOX_NAME];
    WCHAR* v2;
    ULONG v3;
    MemoryZero(v1, sizeof(v1));
    if (Process)
        wcscpy(v1, Process->Box->BoxName);   //获取BoxName
    v2 = (WCHAR*)ParameterData[2];
    if ((!v1[0]) && v2) {
        ProbeForRead(v2, sizeof(WCHAR) * (BOX_NAME - 2), sizeof(UCHAR));
        if (v2[0])
            wcsncpy(v1, v2, (BOX_NAME - 2));
    }


    // get "all users/current user only" flag from third parameter

    IsAllSessions = FALSE;
    if (ParameterData[3])
        IsAllSessions = TRUE;

    SessionIdentity = (ULONG)ParameterData[4];

    // get user pid buffer from first parameter

    Count = (ULONG*)ParameterData[5];
    ProcessIdentitys = (ULONG*)ParameterData[1];

    if (Count) {
        ProbeForRead(Count, sizeof(ULONG), sizeof(ULONG));
        v3 = ProcessIdentitys ? *Count : 0;
    }
    else // legacy case
    {
        if (!ProcessIdentitys)
            return STATUS_INVALID_PARAMETER;
        v3 = MAX_PIDS - 1;
        Count = ProcessIdentitys;
        ProcessIdentitys += 1;
    }


    ProbeForWrite(Count, sizeof(ULONG), sizeof(ULONG));
    if (ProcessIdentitys) {
        ProbeForWrite(ProcessIdentitys, sizeof(ULONG) * v3, sizeof(ULONG));
    }


    Status = EnumerateProcess(v1, IsAllSessions, SessionIdentity,
        ProcessIdentitys, &v3);
    if (!NT_SUCCESS(Status))
        return Status;

    *Count = v3;

    return Status;
}


NTSTATUS GetFileName(PROCESS* Process, ULONG64* ParameterData)
{
    API_GET_FILE_NAME_ARGS* Arguments = (API_GET_FILE_NAME_ARGS*)ParameterData;
    void* Object;
    NTSTATUS Status;

    Status = ObReferenceObjectByHandle(
        Arguments->FileHandle.Value, 0, NULL, UserMode, &Object, NULL);     //通过句柄获取对象

    if (NT_SUCCESS(Status)) {

        POOL* Pool = Process ? Process->Pool : __Pool;
        OBJECT_NAME_INFORMATION* ObjectNameInfo = NULL;
        ULONG NameLength, v2;
        WCHAR* NameData;
        ULONG* DataLength;
        WCHAR* v7;
        ULONG  v8;

        __try {

            void* v10 = Object;
            wchar_t* Buffer = NULL;
            ULONG Length = 0;

            POBJECT_TYPE ObjectType = __ObGetObjectType(Object);   //通过对象获得对象类型
            if (*IoFileObjectType == ObjectType) {

                FILE_OBJECT* FileObject = (FILE_OBJECT*)Object;


                if (FileObject->DeviceObject->DeviceType != FILE_DEVICE_DISK)
                {
                    v10 = FileObject->DeviceObject;

                    if (FileObject->FileName.Buffer && FileObject->DeviceObject->DeviceType != FILE_DEVICE_CONSOLE)
                    {
                        Buffer = FileObject->FileName.Buffer;
                        Length = FileObject->FileName.Length;


                        if (FileObject->DeviceObject->DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
                        {
                            if (Buffer[1] == L';') {
                                wchar_t* v1 = wcschr(Buffer + 2, L'\\');
                                if (v1) {
                                    Length -= (ULONG)(v1 - Buffer);
                                    Buffer = v1;
                                }
                            }
                        }
                    }

                }
            }
            
            v7 = Arguments->ObjectType.Value;  
            if (v7) {

                v8 = ObjectType->Name.Length + sizeof(WCHAR);

                ProbeForWrite(v7, v8, sizeof(WCHAR));   //向Ring3写入类型数据

                memcpy(v7, ObjectType->Name.Buffer, ObjectType->Name.Length);
                v7 += ObjectType->Name.Length / sizeof(wchar_t);
                *v7 = L'\0';
            }
            //判断Ring3写入对象名称数据
            NameData = Arguments->NameData.Value;   
            DataLength = Arguments->DataLength.Value;
            if (!NameData || !DataLength)
                __leave;
              
            Status = GetObjectName(Pool, v10, &ObjectNameInfo, &NameLength);
            if (NT_SUCCESS(Status) && (ObjectNameInfo == &__UnnamedObject)) {
                ObjectNameInfo = NULL;
              
            }
          
            if (NT_SUCCESS(Status))
            {
                //向Ring3写入对象名称数据
                v2 = sizeof(WCHAR);
                if (ObjectNameInfo) {
                    v2 += ObjectNameInfo->Name.Length;
                    if (Buffer)
                        v2 += Length;
                }

                //将数据的长度向Ring3返回
                ProbeForWrite(DataLength, sizeof(ULONG), sizeof(ULONG));

                if (v2 > *DataLength)
                    Status = STATUS_BUFFER_TOO_SMALL;
                else {

                    ProbeForWrite(NameData, v2, sizeof(WCHAR));

                    if (ObjectNameInfo) {
                        memcpy(NameData, ObjectNameInfo->Name.Buffer, ObjectNameInfo->Name.Length);
                        NameData += ObjectNameInfo->Name.Length / sizeof(WCHAR);
                        if (Buffer) {
                            memcpy(NameData, Buffer, Length);
                            NameData += Length / sizeof(WCHAR);
                        }
                    }
                    *NameData = L'\0';

                    Status = STATUS_SUCCESS;
                }

                *DataLength = v2;
            }
          

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (ObjectNameInfo)
            FreeMemoryEx(ObjectNameInfo, NameLength);

        ObDereferenceObject(Object);
    }

    return Status;
}

NTSTATUS CreateDirOrLink(PROCESS* Process, ULONG64* ParameterData)
{
    API_CREATE_DIR_OR_LINK_ARGS* Arguments =
        (API_CREATE_DIR_OR_LINK_ARGS*)ParameterData;
    NTSTATUS Status;
    HANDLE DirectoryHandle;
    UNICODE_STRING64* ObjectName;
    WCHAR* Buffer, * v5 = NULL, * v6;
    ULONG Length, v7, v8;
    OBJECT_ATTRIBUTES ObjectAttriutes;
    UNICODE_STRING v2, v3;

    //
    // this API must be invoked by a sandboxed process
    //

    if (!Process)
        return STATUS_NOT_IMPLEMENTED;

    Status = STATUS_SUCCESS;
    DirectoryHandle = NULL;

    //
    // copy first user parameter: objname
    //

    ObjectName = (UNICODE_STRING64*)Arguments->ObjectName.Value;
    ProbeForRead(ObjectName, sizeof(UNICODE_STRING64), sizeof(ULONG_PTR));    //是否可读
    Length = ObjectName->Length;
    Buffer = (WCHAR*)(ULONG_PTR)ObjectName->Buffer;

    if (Length >= sizeof(WCHAR) && Length < 2048 && Buffer) {

        v7 = Length & ~1;
        ProbeForRead(Buffer, v7, sizeof(WCHAR));
        v5 = MemoryPoolAllocate(Process->Pool, v7 + sizeof(WCHAR));
        if (!v5)
            Status = STATUS_INSUFFICIENT_RESOURCES;
        else {
            memcpy(v5, Buffer, v7);
            v5[v7 / sizeof(WCHAR)] = L'\0';
        }
        /*
        kd> db fffff8a0`018f9190
        fffff8a0`018f9190  5c 00 53 00 61 00 6e 00-64 00 62 00 6f 00 78 00  \.S.a.n.d.b.o.x.
        fffff8a0`018f91a0  5c 00 25 00 55 00 53 00-45 00 52 00 25 00 5c 00  \.%.U.S.E.R.%.\.
        fffff8a0`018f91b0  25 00 53 00 41 00 4e 00-44 00 42 00 4f 00 58 00  %.S.A.N.D.B.O.X.
        fffff8a0`018f91c0  25 00 5c 00 53 00 65 00-73 00 73 00 69 00 6f 00  %.\.S.e.s.s.i.o.
        fffff8a0`018f91d0  6e 00 5f 00 25 00 53 00-45 00 53 00 53 00 49 00  n._.%.S.E.S.S.I.
        fffff8a0`018f91e0  4f 00 4e 00 25 00 5c 00-53 00 65 00 73 00 73 00  O.N.%.\.S.e.s.s.
        fffff8a0`018f91f0  69 00 6f 00 6e 00 73 00-00 00 00 00 00 00 00 00  i.o.n.s.........

        
        */

    }
    else
        Status = STATUS_INVALID_PARAMETER;

    if (!NT_SUCCESS(Status))
        return Status;

    //
    // copy second user parameter: target.  note that if we fail here,
    // we don't even bother freeing up memory, since its allocated
    // to the pool of the sandboxed process
    //

    v6 = NULL;
    v8 = 0;

    ObjectName = (UNICODE_STRING64*)Arguments->TargetName.Value;
    if (ObjectName) {

        ProbeForRead(ObjectName, sizeof(UNICODE_STRING64), sizeof(ULONG_PTR));
        Length = ObjectName->Length;
        Buffer = (WCHAR*)(ULONG_PTR)ObjectName->Buffer;

        if (Length >= sizeof(WCHAR) && Length < 2048 && Buffer) {

            v8 = Length & ~1;
            ProbeForRead(Buffer, v8, sizeof(WCHAR));
            v6 = MemoryPoolAllocate(Process->Pool, v8 + sizeof(WCHAR));
            if (!v6)
                Status = STATUS_INSUFFICIENT_RESOURCES;
            else {
                memcpy(v6, Buffer, v8);
                v6[v8 / sizeof(WCHAR)] = L'\0';
            }

        }
        else
            Status = STATUS_INVALID_PARAMETER;
    }

    if (!NT_SUCCESS(Status)) {
        FreeMemoryEx(v5, v7 + sizeof(WCHAR));
        return Status;
    }

    //
    // make sure the paths are within the sandbox
    //

    InitializeObjectAttributes(
        &ObjectAttriutes, &v2,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, // | OBJ_PERMANENT, 
        NULL, NULL);

    RtlInitUnicodeString(&v2, v5);

    /*判断沙箱路径的合法
    if (!Box_IsBoxedPath(proc->box, ipc, &objname))
        status = STATUS_ACCESS_DENIED;*/   
    if (0)
    {

    }
    else if (v6) {

        RtlInitUnicodeString(&v3, v6);

        /* 判读路径合法
        if (!Box_IsBoxedPath(proc->box, ipc, &target))
            status = STATUS_ACCESS_DENIED;
        else {

            Status = ZwCreateSymbolicLinkObject(
                &handle, SYMBOLIC_LINK_ALL_ACCESS, &objattrs, &v3);
        }
        */

        FreeMemoryEx(v6, v8 + sizeof(WCHAR));

    }
    else {

        Status = ZwCreateDirectoryObject(
            &DirectoryHandle, DIRECTORY_ALL_ACCESS, &ObjectAttriutes);

        if (NT_SUCCESS(Status)) {

            /* 设置安全属性
            if (Driver_LowLabelSd) {

                ZwSetSecurityObject(
                    handle, LABEL_SECURITY_INFORMATION, Driver_LowLabelSd);
            }
            */
        }
    }

    if (DirectoryHandle != NULL) {

        //ZwClose(handle);

        /* 数据结构维护
        KIRQL Irql;
        KeRaiseIrql(APC_LEVEL, &Irql);
        ExAcquireResourceExclusiveLite(Ipc_DirLock, TRUE);

        DIR_OBJ_HANDLE* obj_handle = Mem_Alloc(Driver_Pool, sizeof(DIR_OBJ_HANDLE));
        obj_handle->handle = handle;
        List_Insert_After(&Ipc_ObjDirs, NULL, obj_handle);

        ExReleaseResourceLite(Ipc_DirLock);
        KeLowerIrql(Irql);*/
    }

    FreeMemoryEx(v5, v7 + sizeof(WCHAR));

    if (Status == STATUS_OBJECT_NAME_COLLISION)
        Status = STATUS_SUCCESS;

    return Status;
}