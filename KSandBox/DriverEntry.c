#include "DriverEntry.h"
#include "SystemHelper.h"
#include "ObjectHelper.h"
#include "MemoryPool.h"
#include "PeHelper.h"
#include "ProcessHelper.h"
#include "ApiHelper.h"
#include "GuiHelper.h"
#include "FileHelper.h"
#include "IpcHelper.h"
//DriverObject

//bp KSandBox!DriverEntry


DRIVER_OBJECT* __DriverObject = NULL;;
volatile BOOLEAN __ReadyToSandbox = FALSE;  
WCHAR* __DriverVersion = TEXT(DRIVER_VERSION);     

volatile BOOLEAN __IsDriverUnloading = FALSE;

const WCHAR* __S_1_5_18 = L"S-1-5-18"; //	System
const WCHAR* __S_1_5_19 = L"S-1-5-19"; //	Local Service
const WCHAR* __S_1_5_20 = L"S-1-5-20"; //	Network Service



NTSTATUS DriverEntry(
    IN  PDRIVER_OBJECT DriverObject,
    IN  PUNICODE_STRING RegistryPath)
{
    BOOLEAN IsOk = TRUE;

    //服务程序加载执行

    HANDLE ProcessIdentity = PsGetCurrentProcessId();

    PLDR_DATA_TABLE_ENTRY v1 = (PLDR_DATA_TABLE_ENTRY)(DriverObject->DriverSection);
    v1->Flags |= 0x20;

    /*
    kd> dt _LDR_DATA_TABLE_ENTRY
nt!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY
   +0x010 InMemoryOrderLinks : _LIST_ENTRY
   +0x020 InInitializationOrderLinks : _LIST_ENTRY
   +0x030 DllBase          : Ptr64 Void
   +0x038 EntryPoint       : Ptr64 Void
   +0x040 SizeOfImage      : Uint4B
   +0x048 FullDllName      : _UNICODE_STRING
   +0x058 BaseDllName      : _UNICODE_STRING
   +0x068 Flags            : Uint4B
   +0x06c LoadCount        : Uint2B
   +0x06e TlsIndex         : Uint2B
   +0x070 HashLinks        : _LIST_ENTRY
   +0x070 SectionPointer   : Ptr64 Void
   +0x078 CheckSum         : Uint4B
   +0x080 TimeDateStamp    : Uint4B
   +0x080 LoadedImports    : Ptr64 Void
   +0x088 EntryPointActivationContext : Ptr64 _ACTIVATION_CONTEXT
   +0x090 PatchInformation : Ptr64 Void
   +0x098 ForwarderLinks   : _LIST_ENTRY
   +0x0a8 ServiceTagLinks  : _LIST_ENTRY
   +0x0b8 StaticLinks      : _LIST_ENTRY
   +0x0c8 ContextInformation : Ptr64 Void
   +0x0d0 OriginalBase     : Uint8B
   +0x0d8 LoadTime         : _LARGE_INTEGER

    
    */


    //
    //创建进程回调  
    //使用Lpc与Ring3层进行通信
    __DriverObject = DriverObject;

    DriverObject->DriverUnload = DriverUnload;
  


    if (IsOk)
        IsOk = CheckOsVersion();
    
    if (IsOk)
    {
        __Pool = CreateMemoryPool();
        if (!__Pool)
        {
         
            IsOk = FALSE;
        }
    }

    if (IsOk)
        IsOk = CheckHomePath(RegistryPath);   //获得路径
   
    /*
    if (IsOk)
        InitializeDynamicData();
    */



    if (IsOk)
        IsOk = InitializeObject();
    if (IsOk)
        IsOk = InitializeDll();

    if (IsOk)
        IsOk = InitializeSyscalls(); //!!

    if (IsOk)
        IsOk = InitializeProcess();  //!!
    if (IsOk)
        IsOk = InitializeFile();
    if (IsOk)
    {
        IsOk = InitializeCommonData();    //!!
    }
    if (IsOk)
        IsOk = InitializeIpc();

    if (IsOk)
        IsOk = InitializeGui(NULL,NULL);

    return STATUS_SUCCESS;

}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{

    __IsDriverUnloading = TRUE;
    UninitializeDll();
    UninitializeProcess(TRUE);


    UninitializeCommonData();


    if (__Pool)
        DeleteMemoryPool(__Pool);

    DbgPrint(L"DriverUnload()\r\n");


}