#include "ApiHelper.h"
#include "IoRequest.h"
#include "StatusHelper.h"
#include <ntstatus.h>
#include "InjectHelper.h"



ULONG* __SyscallsData = NULL;
LONG GetDriverVersion(
    WCHAR* DriverVersion1,  // WCHAR [16]
    ULONG* DriverVersion2)
{
    NTSTATUS Status;
    __declspec(align(8)) ULONG64 ParameterData[API_NUMBER_ARGS];
    GET_VERSION_ARGS* v1 = (GET_VERSION_ARGS*)ParameterData;

    ZeroMemory(v1, sizeof(ParameterData));
    v1->ServiceIndex = GET_DRIVER_VERSION;
    v1->DriverVersion1.Value = DriverVersion1;   //Ìá¹©ÄÚ´æ
    v1->DriverVersion2.Value = DriverVersion2;

    //Io¿ØÖÆÂë
    Status = IoctlRequestInternal(ParameterData);   //Ring3ÇëÇóRing0

    if (!NT_SUCCESS(Status))
    {
        //ÇëÇóÊ§°Ü
        if (DriverVersion1) memcpy(DriverVersion1, L"Unknown", (wcslen(L"Unknown") + 1) * sizeof(WCHAR));
        if (DriverVersion2) *DriverVersion2 = 0;
    }

    return Status;
}
LONG GetHomePath(
	WCHAR* PathData1, ULONG DataLength1, WCHAR* PathData2, ULONG DataLength2)
{
	NTSTATUS Status;
	__declspec(align(8)) UNICODE_STRING64 NtPath;
	__declspec(align(8)) UNICODE_STRING64 DosPath;
	__declspec(align(8)) ULONG64 ParameterData[API_NUMBER_ARGS];
	GET_HOME_PATH_ARGS* Arguments = (GET_HOME_PATH_ARGS*)ParameterData;

	NtPath.Length = 0;
	NtPath.MaximumLength = (USHORT)(DataLength1 * sizeof(WCHAR));
	NtPath.Buffer = (ULONG64)(ULONG_PTR)PathData1;

	DosPath.Length = 0;
	DosPath.MaximumLength = (USHORT)(DataLength2 * sizeof(WCHAR));
	DosPath.Buffer = (ULONG64)(ULONG_PTR)PathData2;

	ZeroMemory(ParameterData, sizeof(ParameterData));
	Arguments->ServiceIndex = GET_HOME_PATH;
	if (PathData1)
		Arguments->NtPath.Value64 = (ULONG64)(ULONG_PTR)&NtPath;
	if (PathData2)
		Arguments->DosPath.Value64 = (ULONG64)(ULONG_PTR)&DosPath;
	Status = IoctlRequestInternal(ParameterData);

	if (!NT_SUCCESS(Status))
	{
		if (PathData1)
			PathData1[0] = L'\0';
		if (PathData2)
			PathData2[0] = L'\0';
	}

	return Status;
}



ULONG QuerySyscalls(BOOLEAN IsDriver)
{
	const WCHAR* Dll = L"\\" DLL L".dll";
	WCHAR HomePath[512];
	NTSTATUS Status;
	ULONG* SyscallsData;
	ULONG v7 = 0;
	EXTRA_DATA_INFO* ExtraDataInfo;
	WCHAR* v1;
#ifdef _M_ARM64

#endif

	if (IsDriver)
	{
		Status = GetHomePath(NULL, 0, HomePath, 512);
		//HomePath = 0x0000000002a7f1b0 L"C:\\Users\\Shine\\Desktop"




		if (Status != 0)
			return Status;
	}
	else
	{
		GetModuleFileName(NULL,HomePath, 512);
		v1 = wcsrchr(HomePath, L'\\');
		if (v1)
			*v1 = L'\0';
	}


	if (!__SyscallsData)
	{
		SyscallsData = (ULONG*)HeapAlloc(GetProcessHeap(), 0, 8192);
		if (!SyscallsData)
			return STATUS_INSUFFICIENT_RESOURCES;
		*SyscallsData = 0;
	}
	else
		SyscallsData = __SyscallsData;

	if (IsDriver)
	{
		//
		// Get a full sys call list from the driver
		//

		Status = IoctlRequest(QUERY_SYSCALLS, 1, (ULONG_PTR)SyscallsData);
		if (Status != 0)
			return Status;


		/*
		kd> db 00000000`00469660
00000000`00469660  e0 0c 00 00 00 00 00 00-60 00 00 00 e0 18 05 00  ........`.......
00000000`00469670  61 00 00 00 f0 18 05 00-26 00 00 00 40 15 05 00  a.......&...@...
00000000`00469680  62 00 00 00 00 19 05 00-56 00 00 00 40 18 05 00  b.......V...@...
00000000`00469690  63 00 00 00 10 19 05 00-64 00 00 00 20 19 05 00  c.......d... ...
00000000`004696a0  65 00 00 00 30 19 05 00-44 00 00 00 20 17 05 00  e...0...D... ...
00000000`004696b0  66 00 00 00 40 19 05 00-67 00 00 00 50 19 05 00  f...@...g...P...
00000000`004696c0  68 00 00 00 60 19 05 00-3e 00 00 00 c0 16 05 00  h...`...>.......
00000000`004696d0  69 00 00 00 70 19 05 00-6a 00 00 00 80 19 05 00  i...p...j.......

		
		*/



		v7 = *SyscallsData;
		if ((!v7) || (v7 & 3) || (v7 > 4096))
			return STATUS_INVALID_IMAGE_FORMAT;



	}
	else
	{

	}
	ExtraDataInfo = (EXTRA_DATA_INFO*)((ULONG_PTR)SyscallsData + v7);

	SyscallsData[1] = v7;

	//
	// write an ASCII string for LdrLoadDll (see core/low/inject.c)
	//

	v1 = (WCHAR*)((ULONG_PTR)ExtraDataInfo + sizeof(EXTRA_DATA_INFO));

	strcpy((char*)v1, "LdrLoadDll");

	//SyscallsData
	//
	//

	//SyscallsExtraData
	//
	//
	//
	//



	ExtraDataInfo->LdrLoadDllOffset = ULONG_DIFF(v1, ExtraDataInfo);
	v1 += 16 / sizeof(WCHAR);

	//
	// write an ASCII string for LdrGetProcedureAddress
	//

	strcpy((char*)v1, "LdrGetProcedureAddress");

	ExtraDataInfo->LdrGetProcAddrOffset = ULONG_DIFF(v1, ExtraDataInfo);
	v1 += 28 / sizeof(WCHAR);

	//
	// write an ASCII string for NtProtectVirtualMemory
	//

	strcpy((char*)v1, "NtProtectVirtualMemory");

	ExtraDataInfo->NtProtectVirtualMemoryOffset = ULONG_DIFF(v1, ExtraDataInfo);
	v1 += 28 / sizeof(WCHAR);


	strcpy((char*)v1, "NtRaiseHardError");

	ExtraDataInfo->NtRaiseHardErrorOffset = ULONG_DIFF(v1, ExtraDataInfo);
	v1 += 20 / sizeof(WCHAR);

	//
	// write an ASCII string for NtDeviceIoControlFile
	//

	strcpy((char*)v1, "NtDeviceIoControlFile");

	ExtraDataInfo->NtDeviceIoControlFileOffset = ULONG_DIFF(v1, ExtraDataInfo);
	v1 += 28 / sizeof(WCHAR);

	//
	// write an ASCII string for RtlFindActivationContextSectionString
	//

	strcpy((char*)v1, "RtlFindActivationContextSectionString");

	ExtraDataInfo->RtlFindActCtxOffset = ULONG_DIFF(v1, ExtraDataInfo);
	v1 += 44 / sizeof(WCHAR);

#ifdef _M_ARM64
	//
	// write an ASCII string for LdrQueryImageFileExecutionOptionsEx
	//

	strcpy((char*)v1, "LdrQueryImageFileExecutionOptionsEx");

	ExtraDataInfo->RtlImageOptionsEx_offset = ULONG_DIFF(v1, ExtraDataInfo);
	v1 += 40 / sizeof(WCHAR);
#endif
	wcscpy(v1, L"kernel32.dll");

	v7 = (ULONG)wcslen(v1);
	ExtraDataInfo->KernelDllOffset = ULONG_DIFF(v1, ExtraDataInfo);
	ExtraDataInfo->KernelDllLength = v7 * sizeof(WCHAR);
	v1 += v7 + 1;

	//
	// append paths for native and wow64 SbieDll to the syscall buffer
	//

	wcscpy(v1, HomePath);
	wcscat(v1, Dll);

	//v1 = 0x000000000026a43e L"C:\\Users\\Shine\\Desktop\\Dll.dll"


	v7 = (ULONG)wcslen(v1);
	ExtraDataInfo->NativeDllOffset = ULONG_DIFF(v1, ExtraDataInfo);
	ExtraDataInfo->NativeDllLength = v7 * sizeof(WCHAR);
	v1 += v7 + 1;



#ifdef _M_ARM64
	
#endif

#ifdef _WIN64

	
#endif _WIN64

	/*
	0x0000000000269660  e0 0c 00 00 e0 0c 00 00 4c 8b d1 b8 31 00 00 00 0f 05 c3 0f 1f 44 00 00 4c 8b d1 b8 32 00 00 00 0f 05 c3 0f 1f 44 00 00 4c 8b d1 b8  ?...?...L???1.....?..D..L???2.....?..D..L???
	0x000000000026968C  04 00 00 00 0f 05 c3 0f 1f 44 00 00 4c 8b d1 b8 05 00 00 00 0f 05 c3 0f 1f 44 00 00 4c 8b d1 b8 c2 00 00 00 0f 05 c3 0f 1f 44 00 00  ......?..D..L???......?..D..L????.....?..D..
	0x00000000002696B8  4c 8b d1 b8 c3 00 00 00 0f 05 c3 0f 1f 44 00 00 4c 8b d1 b8 4d 00 00 00 0f 05 c3 0f 1f 44 00 00 4c 8b d1 b8 4e 00 00 00 0f 05 c3 0f  L????.....?..D..L???M.....?..D..L???N.....?.
	0x00000000002696E4  1f 44 00 00 61 00 00 00 f0 18 05 00 26 00 00 00 40 15 05 00 62 00 00 00 00 19 05 00 56 00 00 00 40 18 05 00 63 00 00 00 10 19 05 00  .D..a...?...&...@...b.......V...@...c.......
	0x0000000000269710  64 00 00 00 20 19 05 00 65 00 00 00 30 19 05 00 44 00 00 00 20 17 05 00 66 00 00 00 40 19 05 00 67 00 00 00 50 19 05 00 68 00 00 00  d... ...e...0...D... ...f...@...g...P...h...
	0x000000000026973C  60 19 05 00 3e 00 00 00 c0 16 05 00 69 00 00 00 70 19 05 00 6a 00 00 00 80 19 05 00 6b 00 00 00 90 19 05 00 6c 00 00 00 a0 19 05 00  `...>...?...i...p...j...€...k...?...l...?...
	0x0000000000269768  6d 00 00 00 b0 19 05 00 6e 00 00 00 c0 19 05 00 15 00 00 00 30 14 05 00 6f 00 00 00 d0 19 05 00 70 00 00 00 e0 19 05 00 71 00 00 00  m...?...n...?.......0...o...?...p...?...q...
	0x0000000000269794  f0 19 05 00 72 00 00 00 00 1a 05 00 73 00 00 00 10 1a 05 00 74 00 00 00 20 1a 05 00 75 00 00 00 30 1a 05 00 76 00 00 00 40 1a 05 00  ?...r.......s.......t... ...u...0...v...@...
	0x00000000002697C0  77 00 00 00 50 1a 05 00 78 00 00 00 60 1a 05 00 79 00 00 00 70 1a 05 00 7a 00 00 00 80 1a 05 00 7b 00 00 00 90 1a 05 00 7c 00 00 00  w...P...x...`...y...p...z...€...{...?...|...
	0x00000000002697EC  a0 1a 05 00 7d 00 00 00 b0 1a 05 00 7e 00 00 00 c0 1a 05 00 7f 00 00 00 d0 1a 05 00 82 00 00 00 00 1b 05 00 83 00 00 00 10 1b 05 00  ?...}...?...~...?.......?...?.......?.......
	0x0000000000269818  84 00 00 00 20 1b 05 00 96 00 00 00 40 1c 05 00 1a 00 00 00 80 14 05 00 9a 00 00 00 80 1c 05 00 9d 00 00 00 b0 1c 05 00 39 00 00 00  ?... ...?...@.......€...?...€...?...?...9...
	0x0000000000269844  70 16 05 00 c6 00 00 00 40 1f 05 00 ca 00 00 00 80 1f 05 00 d7 00 00 00 50 20 05 00 d9 00 00 00 70 20 05 00 db 00 00 00 90 20 05 00  p...?...@...?...€...?...P ..?...p ..?...? ..
	0x0000000000269870  df 00 00 00 d0 20 05 00 e2 00 00 00 00 21 05 00 e7 00 00 00 50 21 05 00 25 00 00 00 30 15 05 00 5c 00 00 00 a0 18 05 00 08 01 00 00  ?...? ..?....!..?...P!..%...0...\...?.......
	0x000000000026989C  60 23 05 00 09 01 00 00 70 23 05 00 4d 00 00 00 b0 17 05 00 3a 00 00 00 80 16 05 00 53 00 00 00 10 18 05 00 19 01 00 00 70 24 05 00  `#......p#..M...?...:...€...S...........p$..
	0x00000000002698C8  13 00 00 00 10 14 05 00 1f 01 00 00 d0 24 05 00 2a 01 00 00 80 25 05 00 40 01 00 00 e0 26 05 00 43 01 00 00 10 27 05 00 44 01 00 00  ............?$..*...€%..@...?&..C....'..D...
	0x00000000002698F4  20 27 05 00 47 01 00 00 50 27 05 00 4c 01 00 00 a0 27 05 00 52 01 00 00 00 28 05 00 0b 00 00 00 90 13 05 00 59 01 00 00 70 28 05 00   '..G...P'..L...?'..R....(......?...Y...p(..
	0x0000000000269920  0a 00 00 00 80 13 05 00 5f 01 00 00 d0 28 05 00 64 01 00 00 20 29 05 00 65 01 00 00 30 29 05 00 6c 01 00 00 a0 29 05 00 81 01 00 00  ....€..._...?(..d... )..e...0)..l...?)..?...
	0x000000000026994C  f0 2a 05 00 83 01 00 00 10 2b 05 00 84 01 00 00 20 2b 05 00 58 00 00 00 60 18 05 00 00 00 00 00 00 00 00 00 dd dd dd dd dd dd dd dd  ?*..?....+..?... +..X...`...........????????
	0x0000000000269978  dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd  ????????????????????????????????????????????
	0x00000000002699A4  dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd  ????????????????????????????????????????????


	
	0x000000000026A318  dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd 40 00 00 00  ????????????????????????????????????????@...
	0x000000000026A344  50 00 00 00 6c 00 00 00 88 00 00 00 9c 00 00 00 b8 00 00 00 e4 00 00 00 18 00 00 00 fe 00 00 00 3c 00 00 00 dd dd dd dd dd dd dd dd  P...l...?...?...?...?.......?...<...????????
	0x000000000026A370  dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd 4c 64 72 4c 6f 61 64 44 6c 6c 00 dd dd dd dd dd 4c 64 72 47 65 74 50 72 6f 63 65 64  ????????????????LdrLoadDll.?????LdrGetProced
	0x000000000026A39C  75 72 65 41 64 64 72 65 73 73 00 dd dd dd dd dd 4e 74 50 72 6f 74 65 63 74 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 dd dd dd dd dd  ureAddress.?????NtProtectVirtualMemory.?????
	0x000000000026A3C8  4e 74 52 61 69 73 65 48 61 72 64 45 72 72 6f 72 00 dd dd dd 4e 74 44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c 46 69 6c 65 00 dd dd  NtRaiseHardError.???NtDeviceIoControlFile.??
	0x000000000026A3F4  dd dd dd dd 52 74 6c 46 69 6e 64 41 63 74 69 76 61 74 69 6f 6e 43 6f 6e 74 65 78 74 53 65 63 74 69 6f 6e 53 74 72 69 6e 67 00 dd dd  ????RtlFindActivationContextSectionString.??
	0x000000000026A420  dd dd dd dd 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00  ????k.e.r.n.e.l.3.2...d.l.l...C.:.\.U.s.e.r.
	0x000000000026A44C  73 00 5c 00 53 00 68 00 69 00 6e 00 65 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 44 00 6c 00 6c 00 2e 00 64 00 6c 00  s.\.S.h.i.n.e.\.D.e.s.k.t.o.p.\.D.l.l...d.l.
	0x000000000026A478  6c 00 00 00 dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd  l...????????????????????????????????????????
	
	*/
	ExtraDataInfo->InjectDataOffset = ULONG_DIFF(v1, ExtraDataInfo);


	ExtraDataInfo->Lock = 0;


	//
	// adjust size of syscall buffer to include path strings
	//

	*SyscallsData = ULONG_DIFF(v1, SyscallsData) + sizeof(INJECT_DATA);

	__SyscallsData = SyscallsData;


#ifdef _M_ARM64
#endif



	return STATUS_SUCCESS;
}