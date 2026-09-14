
#include "_tWinMain.h"
#include "DriverAssist.h"
#include "IoRequest.h"
#include "MemoryHelper.h"
#include "FileHelper.h"
static  WCHAR _ServiceName[] = L"SandBox";



HMODULE  __Ntdll = NULL;
HMODULE  __Kernel32 = NULL; 
SYSTEM_INFO           __SystemInfo;
ULONG    __Windows = 0;
INT WINAPI _tWinMain(
	_In_ HINSTANCE Instance,
	_In_opt_ HINSTANCE PrevInstance,
	_In_ PTSTR CmdLine,
	_In_ INT CmdShow
)
{
	int LastError = 0;


	__Ntdll = GetModuleHandle(_T("ntdll.dll"));
	__Kernel32 = GetModuleHandle(_T("kernel32.dll"));
	
	GetSystemInfo(&__SystemInfo);

	InitializeIoDevice();   //获取Ntdll中的导出函数


	InitializeMemory();     
	InitializeFile();

	/*
	
	SERVICE_TABLE_ENTRY ServiceTableEntry[] = 
	{
	  { _ServiceName, ServiceMain },
	  { NULL, NULL }
	};


	if (!StartServiceCtrlDispatcher(ServiceTableEntry))
	{

		LastError = GetLastError();
	}
	MessageBox(NULL, _T("_tWinMain()"), _T("_tWinMain()"), NULL);*/


	bool IsOk = CDriverAssist::Initialize();



	Sleep(INFINITE);

	
	return LastError;
}
void WINAPI ServiceMain(DWORD argc, WCHAR* argv[])
{

	
	int v1 = 0;
}