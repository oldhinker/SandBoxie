
#include "ExportServices.h"
#include "InjectionHelper.h"

DATA_INFO* __DataInfo = NULL;
HANDLE __DeviceHandle = INVALID_HANDLE_VALUE;
#ifndef _WIN64
BOOLEAN  __IsWow64 = FALSE;
#endif
ULONG __ProcessIdentity = 0;
ULONG __SessionIdentity = 0;
ULONG __DriverFlags = 0;
ULONG64 __ProcessFlags = 0;


VOID Dll_Ordinal1(INJECT_DATA* InjectData)
{
	LoadLibrary(_T("User32.dll"));
	MessageBox(NULL, _T("SandBox"), _T("SandBox"), 0);





    DATA_INFO* DataInfo = (DATA_INFO*)InjectData->DataInfo;
    BOOLEAN IsHostInject = FALSE;

    __DataInfo = DataInfo;
#ifdef _M_ARM64EC

#endif

  
    __DeviceHandle = (HANDLE)DataInfo->DeviceHandle;

    IsHostInject = DataInfo->Flags.bHostInject == 1;

#ifndef _WIN64
    __IsWow64 = DataInfo->Flags.is_wow64 == 1; // x86 on x64 or arm64
#endif
#ifdef _M_ARM64EC
#endif
#ifndef _WIN64
 
#endif
    if (!IsHostInject)
    {
        PrepareInjection(); // install required hooks (Dll_InitInjected -> Ldr_Init -> Ldr_Inject_Init(FALSE))
    }
    else
    {

    }

}
