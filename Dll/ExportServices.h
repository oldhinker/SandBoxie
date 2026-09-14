#pragma once
#include "Common.h"
#include "StringHelper.h"

#define NATIVE_FUNCTION_COUNT   4
#define NATIVE_FUNCTION_SIZE    32
typedef union _DATA_FLAGS {
	ULONG	init_flags;
	struct {
		ULONG
			is_wow64 : 1,
			is_arm64ec : 1,
			is_xtajit : 1,
			is_chpe32 : 1,
			reservd_1 : 4,

			long_diff : 1,
			hook_dbg : 1,
			reservd_2 : 6,

			bHostInject : 1,
			bNoSysHooks : 1,
			bNoConsole : 1,
			reservd_3 : 5,

			is_win10 : 1,
			reservd_4 : 7;
	};
}DATA_FLAGS;

typedef struct _DATA_INFO_ {
	ULONG64     Ntdll;
	ULONG64     SyscallsData;        //目标进程当前结构的首地址

	ULONG64     DeviceHandle;
	ULONG       IoControlCode;
	ULONG       InvokeSyscalls;

	DATA_FLAGS Flags;
	UCHAR       IsInitializeDone;
	UCHAR       reserved[3];

	__declspec(align(16))
		UCHAR   LdrInitializeThunk_tramp[48];

	__declspec(align(16))
		UCHAR   NtDelayExecution_code[NATIVE_FUNCTION_SIZE];
	__declspec(align(16))
		UCHAR   NtDeviceIoControlFile_code[NATIVE_FUNCTION_SIZE];     // offset 128
	__declspec(align(16))
		UCHAR   NtFlushInstructionCache_code[NATIVE_FUNCTION_SIZE];   // offset 160
	__declspec(align(16))
		UCHAR   NtProtectVirtualMemory_code[NATIVE_FUNCTION_SIZE];

	ULONG64     NtDeviceIoControlFile;          // offset 224   //函数指针
	ULONG64     ArmNtDeviceIoControlFile;      // for ARM64 // offset 232
	ULONG64     NtProtectVirtualMemory;       // offset 240
	ULONG64     NtRaiseHardError;             // offset 248

	ULONG64     SystemService;                //存储汇编函数地址

#ifdef _WIN64
	//SBIELOW_J_TABLE* x64BitJumpTable;

	ULONG64     ntdll_wow64_base;
	ULONG64     ptr_32bit_detour;
#endif

#ifdef _M_ARM64
	__declspec(align(16))
		UCHAR   RtlImageOptionsEx_tramp[48];
#endif

} DATA_INFO;



typedef struct _INJECT_DATA {

    ULONG64 DataInfo;           // 0

    ULONG64 RtlFindActCtx;          // 8
    ULONG RtlFindActCtx_Protect;
    UCHAR RtlFindActCtx_Bytes[20];

    ULONG64 LdrLoadDll;
    ULONG64 LdrGetProcAddr;
    ULONG64 NtProtectVirtualMemory;
    ULONG64 NtRaiseHardError;
    ULONG64 NtDeviceIoControlFile;
    ULONG64 DeviceHandle;

    UNIVERSAL_STRING KernelDll;
    UNIVERSAL_STRING NativeDll;

} INJECT_DATA;



extern ULONG __ProcessIdentity;
extern HANDLE __DeviceHandle;
extern ULONG __SessionIdentity;
extern ULONG __DriverFlags;
extern ULONG64 __ProcessFlags;