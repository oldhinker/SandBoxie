#include "DriverAssist.h"
#include "InjectHelper.h"
#include "StringHelper.h"
#include "IoRequest.h"
#include "ApiHelper.h"
#include "SystemHelper.h"

CDriverAssist* CDriverAssist::m_Instance = nullptr;
bool CDriverAssist::Initialize()
{
    m_Instance = new CDriverAssist();  //单例模式
    ULONG ThreadIdentity;
    HANDLE ThreadHandle;

    if (!m_Instance) {
        return false;
    }

    if (!m_Instance->InitializeInjeciton())    //
    {
        return false;
    }



    if (!m_Instance->InitializePortAndThreads()) 
    {
        return false;
    }


    ThreadHandle = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)StartDriverAsync, m_Instance, 0, &ThreadIdentity);
    CloseHandle(ThreadHandle);

    return true;
}

CDriverAssist::CDriverAssist()
{
    m_PortHandle = NULL;
    m_IsDriverReady = TRUE;
}
CDriverAssist::~CDriverAssist()
{

}

bool CDriverAssist::InitializeInjeciton()
{
    ULONG Error = InjecitonPrepare();
    if (Error != 0) 
    {
        return false;
    }

    return true;
}
bool CDriverAssist::InitializePortAndThreads()
{
    NTSTATUS Status;
    UNICODE_STRING v1;
    OBJECT_ATTRIBUTES ObjectAttributes;
    WCHAR PortName[64];
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    ULONG i, n;

    static const WCHAR* _PortName = L"\\RPC Control\\" NAME L"Port";
    // create LPC port which the driver will use to send us messages
    // the port must have a name, or LpcRequestPort in SbieDrv will fail
    //

    //创建安全属性


    wsprintf(PortName, L"%s-internal-%d", _PortName, GetTickCount());
    RtlInitUnicodeString(&v1, PortName);

    InitializeObjectAttributes(
        &ObjectAttributes, &v1, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = __NtCreatePort(
        (HANDLE*)&m_PortHandle, &ObjectAttributes, 0, MAX_MESSAGE_LENGTH, NULL);

    if (!NT_SUCCESS(Status)) {
      
        return false;
    }


    InterlockedExchangePointer(&m_PortHandle, m_PortHandle);

    //
    // create the worker threads
    //


    //动态申请线程句柄
    n = (NUMBER_OF_THREADS) * sizeof(HANDLE);
    m_ThreadHandles = (HANDLE*)HeapAlloc(GetProcessHeap(), 0, n);
    if (!m_ThreadHandles)
    {
     
        return false;
    }
    ZeroMemory(m_ThreadHandles, n);

    for (i = 0; i < NUMBER_OF_THREADS; ++i) {

        m_ThreadHandles[i] = CreateThread(NULL, 0, ::ReceiveMessageThread, this, 0, &n);
        if (!m_ThreadHandles[i]) {
        
            return false;
        }
    }

    return true;
}

DWORD WINAPI ReceiveMessageThread(void* ParameterData)
{

    ((CDriverAssist*)ParameterData)->ReceiveMessageThread();

    return 0;

}
DWORD WINAPI HandleMessageThread(void* ParameterData)
{

    if (!ParameterData) {
        return -1;
    }
    MESSAGE_DATA* MessageData = (MESSAGE_DATA*)ParameterData;
    ((CDriverAssist*)MessageData)->HandleMessageThread(MessageData->BufferData);

    VirtualFree(ParameterData, 0, MEM_RELEASE);

    return NO_ERROR;
}


void CDriverAssist::ReceiveMessageThread()
{
    NTSTATUS Status;
    HANDLE ThreadHandle;
    DWORD ThreadIdentity;
  
    MESSAGE_DATA*  MessageData;

    //等待Ring0通过端口回传数据
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    while (1) {

        MessageData = (MESSAGE_DATA*)VirtualAlloc(0, sizeof(MESSAGE_DATA), MEM_COMMIT, PAGE_READWRITE);
        if (!MessageData)
        {
            break;  // out of memory
        }

        Status = __NtReplyWaitReceivePort(m_PortHandle, NULL, NULL, (PORT_MESSAGE*)MessageData->BufferData);

        if (!m_PortHandle) {    // service is shutting down
            VirtualFree(MessageData, 0, MEM_RELEASE);
            break;
        }

        //分析Ring0层回传的数据
        MessageData->ClassContext = this;
        ThreadHandle = CreateThread(NULL, 0, ::HandleMessageThread, (void*)MessageData, 0, &ThreadIdentity);
        if (ThreadHandle)
            CloseHandle(ThreadHandle);
        else
            VirtualFree(MessageData, 0, MEM_RELEASE);
    }
}
void CDriverAssist::HandleMessageThread(void* ParameterData)
{

    PORT_MESSAGE* PortMessage = (PORT_MESSAGE*)ParameterData;
    //Null pointer checked by caller
    if (PortMessage->u2.s2.Type != LPC_DATAGRAM) 
    {
        return;
    }
    ULONG DataLength = PortMessage->u1.s1.DataLength;
    if (DataLength < sizeof(ULONG)) {
        return;
    }
    DataLength -= sizeof(ULONG);

    ULONG* MessageData = (ULONG*)((UCHAR*)PortMessage + sizeof(PORT_MESSAGE));    //回传上来的真正数据
    ULONG Protocol = *MessageData;
    ++MessageData;

  
    if (Protocol == INJECT_PROCESS) {

        InjectProcessReply(MessageData);

    }
   
}


ULONG CDriverAssist::StartDriverAsync(void* ParameterData)
{
    CDriverAssist* This = (CDriverAssist*)ParameterData;

    //
    // get windows version
    //

    OSVERSIONINFOEX	OsVersionInfoEx;
    OsVersionInfoEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((OSVERSIONINFO*)&OsVersionInfoEx);

    //
    // start the driver, but only if it isn't already active
    //

    bool IsOk = false;

    LONG Status = GetDriverVersion(NULL, NULL);
    if (Status == 0) {
        IsOk = true;
        goto driver_started;
    }





driver_started:

    if (IsOk) 
    {
        ULONG v10 = 0;

        for (ULONG i = 0; i < 20; ++i) {

            Status = GetDriverVersion(NULL, &v10);
            if (Status == 0)
                break;
            Sleep(500);
        }

        if (v10 != DRIVER_VERSION)
        {
          
            IsOk = false;
        }
    }
    if (IsOk)
    {

    }

    if (IsOk) 
    {
        Status = IoctlRequest(SET_SERVICE_PORT, 1, (ULONG_PTR)m_Instance->m_PortHandle);
        if (Status != 0) {
          
            IsOk = false;
        }

    }

    if (IsOk) {
        Status = QuerySyscalls(TRUE);
        if (Status != 0) {
         
            IsOk = false;
        }
    }
    if (IsOk) {

    
        Status = IoctlRequest(START_PROCESS_NOTIFY, 0);

        if (Status != 0) {
     
            IsOk = false;
        }
    }
    return 0;
}
