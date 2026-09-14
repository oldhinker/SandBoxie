#include "IpcHook.h"
#include "MemoryList.h"
#include "dllmain.h"
#include "MemoryHelper.h"
#include "HookHelper.h"
#include "StatusHelper.h"
#include "ObjectHook.h"
#include "InjectionHelper.h"
#include "ApiHelper.h"
static LIST _List1;
static CRITICAL_SECTION _CriticalSection1;


LPFN_NTCREATEPORT               __sys_NtCreatePort = NULL;
LPFN_NTCONNECTPORT              __sys_NtConnectPort = NULL;
LPFN_NTSECURECONNECTPORT        __sys_NtSecureConnectPort = NULL;
LFPN_NTALPCCREATEPORT           __sys_NtAlpcCreatePort = NULL;
LPFN_NTALPCCONNECTPORT          __sys_NtAlpcConnectPort = NULL;
LPFN_NTALPCCONNECTPORTEX        __sys_NtAlpcConnectPortEx = NULL;
LPFN_NTALPCQUERYINFORMATION     __sys_NtAlpcQueryInformation = NULL;
LPFN_NTALPCQUERYINFORMATIONMESSAGE __sys_NtAlpcQueryInformationMessage = NULL;
BOOLEAN IpcHook(void)
{
    HMODULE ModuleHandle = __Ntdll;

    InitializeCriticalSection(&_CriticalSection1);

    InitializeList(&_List1);


    /*
    NtAlpcCreatePort 是 Windows 内核提供的一个系统调用，
    用于创建 ALPC（高级本地过程调用）端口。ALPC 是 Windows 内部的一种高效、安全的进程间通信（IPC）机制，允许内核模式和用户模式之间传递数据。
    */


    void* NtAlpcCreatePort;   
    void* NtAlpcConnectPort;
    void* NtAlpcConnectPortEx;
    void* NtAlpcQueryInformation;
    void* NtAlpcQueryInformationMessage;
    void* NtAlpcImpersonateClientOfPort;
    void* NtAlpcSendWaitReceivePort;

    //
    // initialize cache of open and closed IPC paths
    //

    //SbieDll_MatchPath(L'i', (const WCHAR*)-1);

    //ipc_namespace_isoaltion = SbieApi_QueryConfBool(NULL, L"NtNamespaceIsolation", TRUE);

    //
    // intercept NTDLL entry points
    //

#define DLL_HOOK_IF(Name)                                     \
        Name = GetProcAddress(__Ntdll, #Name);                    \
    if (Name) {                                                   \
        DLL_HOOK(Detour,Name);                                  \
    }

    DLL_HOOK(Detour, NtCreatePort);
    DLL_HOOK(Detour, NtConnectPort);
    DLL_HOOK(Detour, NtSecureConnectPort);


    DLL_HOOK_IF(NtAlpcCreatePort);
    DLL_HOOK_IF(NtAlpcConnectPort);
    DLL_HOOK_IF(NtAlpcConnectPortEx);
    DLL_HOOK_IF(NtAlpcQueryInformation);
    DLL_HOOK_IF(NtAlpcQueryInformationMessage);





    //测试
    DLL_HOOK(Detour, NtCreateEvent);
    DLL_HOOK(Detour, NtOpenEvent);


    DLL_HOOK(Detour, NtOpenDirectoryObject);
    DLL_HOOK(Detour, NtCreateDirectoryObject);





    if (__FirstProcessInBox)
    {
        //DetourCreateObjects();   //创建重定向目录
    }
  


}
void DetourCreateObjects(void)
{


    NTSTATUS Status;
    WCHAR* TruePath;
    WCHAR* CopyPath;
    WCHAR v1[64];
    WCHAR* v3 = NULL;
    WCHAR* v5 = NULL;
    HANDLE RootDirectory = NULL;
    WCHAR* Backslash = NULL;


    snwprintfEx(v1, 64, _BOXED_ L"DummyEvent_%d", __ProcessIdentity);
    RootDirectory = CreateEvent(NULL, FALSE, FALSE, v1);
    if (!RootDirectory) {
       
        Status = GetLastError();
        goto Exit;
    }

    Status = GetName(RootDirectory, NULL, &TruePath, &CopyPath, NULL);
    if (NT_SUCCESS(Status)) {
        if (CopyPath)
            Backslash = wcsrchr(CopyPath, L'\\');
        if (Backslash)
            *Backslash = L'\0';
        else
            Status = STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(Status)) {
     
        goto Exit;
    }

    NtClose(RootDirectory);





    v3 = (WCHAR*)MemoryPoolAllocateEx(__Pool,(wcslen(CopyPath) + 32) * sizeof(WCHAR));

    //
   // create Global directory and symbolic links
   //

    v5 = (WCHAR*)MemoryPoolAllocateEx(__Pool,(__BoxIpcPathLength + 32) * sizeof(WCHAR));

    wcscpy_s(v5, (__BoxIpcPathLength + 32), __BoxIpcPathData);
    wcscat_s(v5, (__BoxIpcPathLength + 32) ,L"\\BaseNamedObjects");

    Status = CreateDirOrLink(v5, NULL);

    if (!NT_SUCCESS(Status)) {
    
        goto Exit;
    }


    wcscpy_s(v3, (wcslen(CopyPath) + 32), CopyPath);
    wcscat_s(v3, (wcslen(CopyPath) + 32), L"\\Session");

    Status = CreateDirOrLink(v3, NULL);

    if (!NT_SUCCESS(Status)) {
      
        goto Exit;
    }
Exit:;
    if (v3)
    {
        MemoryPoolFreeEx(v3);
    }

    if (v5)
        MemoryPoolFreeEx(v5);
}

NTSTATUS DetourNtCreatePort(
    HANDLE* PortHandle,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    ULONG MaxConnectInfoLength,
    ULONG MaxDataLength,
    ULONG* Reserved)
{
    NTSTATUS Status = STATUS_SUCCESS;
    Status = __sys_NtCreatePort(
        PortHandle, ObjectAttributes,
        MaxConnectInfoLength, MaxDataLength, Reserved);
    return Status;
}
NTSTATUS DetourNtConnectPort(
    HANDLE* PortHandle,
    UNICODE_STRING* PortName,
    SECURITY_QUALITY_OF_SERVICE* SecurityQos,
    void* ClientSharedMemory,
    void* ServerSharedMemory,
    ULONG* MaximumMessageLength,
    void* ConnectionInfo,
    ULONG* ConnectionInfoLength)
{

    NTSTATUS Status = STATUS_SUCCESS;
    Status = __sys_NtConnectPort(
        PortHandle, PortName, SecurityQos,
        ClientSharedMemory, ServerSharedMemory,
        MaximumMessageLength, ConnectionInfo, ConnectionInfoLength);
    return Status;
}


NTSTATUS DetourNtSecureConnectPort(
    HANDLE* PortHandle,
    UNICODE_STRING* PortName,
    SECURITY_QUALITY_OF_SERVICE* SecurityQos,
    void* ClientSharedMemory,
    PSID ServerSid,
    void* ServerSharedMemory,
    ULONG* MaximumMessageLength,
    void* ConnectionInfo,
    ULONG* ConnectionInfoLength)
{

    NTSTATUS Status = STATUS_SUCCESS;
    Status = __sys_NtSecureConnectPort(
        PortHandle, PortName, SecurityQos,
        ClientSharedMemory, ServerSid, ServerSharedMemory,
        MaximumMessageLength, ConnectionInfo, ConnectionInfoLength);
    return Status;
}


NTSTATUS DetourNtAlpcCreatePort(
    HANDLE* PortHandle,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    void* AlpcCreateInfo)
{
    NTSTATUS Status = STATUS_SUCCESS;
    Status = __sys_NtAlpcCreatePort(
        PortHandle, ObjectAttributes, AlpcCreateInfo);
    return Status;
}

NTSTATUS DetourNtAlpcConnectPort(
    HANDLE* PortHandle,
    UNICODE_STRING* PortName,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    ALPC_PORT_ATTRIBUTES* AlpcConnectInfo,
    ULONG ConnectionFlags,
    PSID ServerSid,
    void* ConnectionInfo,
    ULONG* ConnectionInfoLength,
    void* InMessageBuffer,
    void* OutMessageBuffer,
    LARGE_INTEGER* Timeout)
{

    NTSTATUS Status = STATUS_SUCCESS;
    Status = __sys_NtAlpcConnectPort(
        PortHandle, PortName, ObjectAttributes,
        AlpcConnectInfo, ConnectionFlags, ServerSid,
        ConnectionInfo, ConnectionInfoLength,
        InMessageBuffer, OutMessageBuffer, Timeout);
    return Status;
}

NTSTATUS DetourNtAlpcConnectPortEx(
    HANDLE* PortHandle,
    OBJECT_ATTRIBUTES* ObjectAttributes1,
    OBJECT_ATTRIBUTES* ObjectAttributes2,
    ALPC_PORT_ATTRIBUTES* AlpcConnectInfo,
    ULONG ConnectionFlags,
    SECURITY_DESCRIPTOR* ServerSd,
    void* ConnectionInfo,
    ULONG* ConnectionInfoLength,
    void* InMessageBuffer,
    void* OutMessageBuffer,
    LARGE_INTEGER* Timeout)
{
    NTSTATUS Status = STATUS_SUCCESS;
    Status = __sys_NtAlpcConnectPortEx(
        PortHandle, ObjectAttributes1, ObjectAttributes2,
        AlpcConnectInfo, ConnectionFlags, ServerSd,
        ConnectionInfo, ConnectionInfoLength,
        InMessageBuffer, OutMessageBuffer, Timeout);
    return Status;
}

NTSTATUS DetourNtAlpcQueryInformation(
    HANDLE* PortHandle,
    ULONG InformationClass,
    void* Information,
    ULONG InformationLength,
    ULONG_PTR UnknownParameter5)
{
    NTSTATUS Status = STATUS_SUCCESS;
    Status = __sys_NtAlpcQueryInformation(
        PortHandle, InformationClass, Information, InformationLength,
        UnknownParameter5);
    return Status;
}


NTSTATUS DetourNtAlpcQueryInformationMessage(
    HANDLE* PortHandle,
    void* RpcMessage,
    ULONG InformationClass,
    void* Information,
    ULONG InformationLength,
    ULONG_PTR UnknownParameter6)
{
    NTSTATUS Status = STATUS_SUCCESS;
    Status = __sys_NtAlpcQueryInformationMessage(
        PortHandle, RpcMessage, InformationClass, Information,
        InformationLength, UnknownParameter6);
    return Status;
}