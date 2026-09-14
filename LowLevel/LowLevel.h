#pragma once

#include <Windows.h>
#include <tchar.h>

#define CALL(x) ((lpfn_##x)&DataInfo->x##_code)

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )


#define NATIVE_FUNCTION_NAMES   { "NtDelayExecution", "NtDeviceIoControlFile", "NtFlushInstructionCache", "NtProtectVirtualMemory" }
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

typedef struct _EXTRA_DATA_INFO_ {

	ULONG LdrLoadDllOffset;
	ULONG LdrGetProcAddrOffset;
	ULONG NtProtectVirtualMemoryOffset;
	ULONG NtRaiseHardErrorOffset;
	ULONG NtDeviceIoControlFileOffset;
	ULONG RtlFindActCtxOffset;
#ifdef _M_ARM64
	ULONG RtlImageOptionsExOffset;
#endif

	ULONG KernelDllOffset;
	ULONG KernelDllLength;

	ULONG NativeDllOffset;
	ULONG NativeDllLength;
#ifdef _M_ARM64
	ULONG Arm64DllOffset;
	ULONG Arm64DllLength;
#endif
	ULONG Wow64DllOffset;
	ULONG Wow64DllLength;

	ULONG InjectDataOffset;

	ULONG_PTR Lock;
}EXTRA_DATA_INFO;





typedef struct _SYSCALL_INFO_ {

	ULONG SyscallNum;
	ULONG SyscallOffset;

} SYSCALL_INFO;

typedef struct _SYSCALLS_DATA_ { // ntdll.dll

	ULONG syscall_data_len;
	ULONG ExtraDataInfoOffset;

	UCHAR CodeData[NATIVE_FUNCTION_SIZE * NATIVE_FUNCTION_COUNT];

	SYSCALL_INFO SyscallsInfo[];

} SYSCALLS_DATA;

void SyscallsPrepare(DATA_INFO* DataInfo, void* SystemService);

