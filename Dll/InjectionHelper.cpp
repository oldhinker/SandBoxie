#include "dllmain.h"
#include "InjectionHelper.h"
#include "ExportServices.h"
#include "ApiHelper.h"
#include "MemoryPool.h"
#include "ObjectHook.h"
#include "StatusHelper.h"
#include "IpcHook.h"
#include "Common.h"

WCHAR* __BoxName;
WCHAR* __ImageName;
WCHAR* __SidString;
BOOLEAN __FirstProcessInBox = FALSE;
void PrepareInjection()
{
	LONG Status;
	BOOLEAN IsOk = TRUE;
	ULONG v1;
	ULONG v2;
	ULONG v3;


	__ProcessIdentity = (ULONG)(ULONG_PTR)GetCurrentProcessId();


	__BoxName = (WCHAR*)MemoryPoolAllocateEx(__Pool,BOX_NAME * sizeof(WCHAR));
	memset(__BoxName, 0,BOX_NAME * sizeof(WCHAR));

	__ImageName = (WCHAR*)MemoryPoolAllocateEx(__Pool,256 * sizeof(WCHAR));
	memset(__ImageName, 0,256 * sizeof(WCHAR));

	__SidString = (WCHAR*)MemoryPoolAllocateEx(__Pool,96 * sizeof(WCHAR));
	memset(__SidString, 0,96 * sizeof(WCHAR));


	Interrupt();
	Status = QueryProcessEx( // sets proc->sbiedll_loaded = TRUE; in the driver
		(HANDLE)(ULONG_PTR)__ProcessIdentity, 255,
		__BoxName, __ImageName, __SidString,
		&__SessionIdentity, NULL);


	if (Status != 0) {
	
		ExitProcess(-1);
	}



	QueryDriverInfo(0, &__DriverFlags, sizeof(__DriverFlags));

	__ProcessFlags = QueryProcessInfoEx(0, 0,0);

	v1 = 0;
	v2 = 0;
	v3 = 0;

	Status = QueryBoxPath(
		NULL, NULL, NULL, NULL,
		NULL, NULL, &v3);
	
	if (Status != 0) {
	
		ExitProcess(-1);
	}

	__BoxIpcPathData = (WCHAR*)MemoryPoolAllocateEx(__Pool,v3);   //用于HookCreateEvent


	Status = QueryBoxPath(
		NULL,
		NULL,
		NULL,
		(WCHAR*)__BoxIpcPathData,
		NULL,NULL, &v3);
	if (Status != 0) {
		
		ExitProcess(-1);
	}

	__BoxIpcPathLength = wcslen(__BoxIpcPathData);





	if (IsOk)
		IsOk = ObjectHook();   //NtQueryObject  NtQueryVirtualMemory


	if (IsOk)
	{
		ULONG Count = 0;

		//获取当前启动的进程信息
		if (NT_SUCCESS(EnumProcessEx(NULL, FALSE, -1, NULL, &Count)) && Count == 1)   //获取当前进程的会话Identity
		{
			__FirstProcessInBox = TRUE;
		}

	}

	if (IsOk)
	{
		IpcHook();
	}

}