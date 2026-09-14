#pragma once
#include "Common.h"
#include "StringHelper.h"
enum {
	FIRST_1 = 0x12340000L,

	GET_DRIVER_VERSION,							//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	GET_WORK_DEPRECATED,    			    // deprecated
	LOG_MESSAGE,
	GET_LICENSE_PRE_V3_48_DEPRECATED,       // deprecated
	SET_LICENSE_PRE_V3_48_DEPRECATED,       // deprecated
	START_PROCESS_PRE_V3_44_DEPRECATED,     // deprecated
	QUERY_PROCESS,
	QUERY_BOX_PATH,
	QUERY_PROCESS_PATH,
	QUERY_PATH_LIST,
	ENUM_PROCESSES,
	DISABLE_FORCE_PROCESS,
	HOOK_TRAMP_DEPRECATED,					// deprecated
	UNMOUNT_HIVES_DEPRECATED,               // deprecated
	QUERY_CONF,
	RELOAD_CONF,
	CREATE_DIR_OR_LINK,
	DUPLICATE_OBJECT,
	GET_INJECT_SAVE_AREA_DEPRECATED,        // deprecated
	RENAME_FILE,
	SET_USER_NAME,
	START_PROCESS_NOTIFY,
	UNLOAD_DRIVER,
	GET_SET_DEVICE_MAP_DEPRECATED,          // deprecated
	SESSION_SET_LEADER_DEPRECATED,          // deprecated
	GLOBAL_FORCE_PROCESS_DEPRECATED,        // deprecated
	MONITOR_CONTROL,
	MONITOR_PUT_DEPRECATED,                 // deprecated
	MONITOR_GET_DEPRECATED,                 // deprecated
	GET_UNMOUNT_HIVE,
	GET_FILE_NAME,
	REFRESH_FILE_PATH_LIST,
	SET_LSA_AUTH_PKG,
	OPEN_FILE,
	SESSION_CHECK_LEADER_DEPRECATED,        // deprecated
	START_PROCESS,
	CHECK_INTERNET_ACCESS,
	GET_HOME_PATH,
	GET_BLOCKED_DLL,
	QUERY_LICENSE,
	ACTIVATE_LICENSE_DEPRECATED,            // deprecated
	OPEN_DEVICE_MAP,
	OPEN_PROCESS,
	QUERY_PROCESS_INFO,
	IS_BOX_ENABLED,
	SESSION_LEADER,
	QUERY_SYMBOLIC_LINK,
	OPEN_KEY,
	SET_LOW_LABEL_KEY,
	OVERRIDE_PROCESS_TOKEN_DEPRECATED,      // deprecated
	SET_SERVICE_PORT,                       //  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	INJECT_COMPLETE,
	QUERY_SYSCALLS,
	INVOKE_SYSCALLS,
	GUI_CLIPBOARD,
	ALLOW_SPOOLER_PRINT_TO_FILE_DEPRECATED, // deprecated
	RELOAD_CONF2,                           // unused
	MONITOR_PUT2,
	GET_SPOOLER_PORT_DEPRECATED,            // deprecated
	GET_WPAD_PORT_DEPRECATED,               // deprecated
	SET_GAME_CONFIG_STORE_PORT_DEPRECATED,  // deprecated
	SET_SMART_CARD_PORT_DEPRECATED,         // deprecated
	MONITOR_GET_EX,
	GET_MESSAGE,
	PROCESS_EXEMPTION_CONTROL,
	GET_DYNAMIC_PORT_FROM_PID,
	OPEN_DYNAMIC_PORT,
	QUERY_DRIVER_INFO,
	FILTER_TOKEN,
	SET_SECURE_PARAM,
	GET_SECURE_PARAM,
	MONITOR_GET2,
	PROTECT_ROOT,
	UNPROTECT_ROOT,
	KILL_PROCESS,
	FORCE_CHILDREN,
	MONITOR_PUT_EX,
	UPDATE_CONF,
	VERIFY,

	LAST_1
};

#define NATIVE_FUNCTION_NAMES   { "NtDelayExecution", "NtDeviceIoControlFile", "NtFlushInstructionCache", "NtProtectVirtualMemory" }
#define NATIVE_FUNCTION_COUNT   4
#define NATIVE_FUNCTION_SIZE    32



#define API_NUMBER_ARGS                8

#define API_ARGS_BEGIN(x)           typedef struct _##x { ULONG64 ServiceIndex;
#define API_ARGS_FIELD(t,m)         union { ULONG64 Value64; t Value; } m;
#define API_ARGS_CLOSE(x)           } x;



API_ARGS_BEGIN(GET_VERSION_ARGS)
API_ARGS_FIELD(WCHAR*, DriverVersion1)
API_ARGS_FIELD(ULONG*, DriverVersion2)
API_ARGS_CLOSE(GET_VERSION_ARGS)

LONG GetDriverVersion(
	WCHAR* DriverVersion1,  // WCHAR [16]
	ULONG* DriverVersion2);


API_ARGS_BEGIN(GET_HOME_PATH_ARGS)
API_ARGS_FIELD(UNICODE_STRING64*, NtPath)
API_ARGS_FIELD(UNICODE_STRING64*, DosPath)
API_ARGS_CLOSE(GET_HOME_PATH_ARGS)
LONG GetHomePath(
	WCHAR* PathData1, ULONG DataLength1, WCHAR* PathData2, ULONG DataLength2);



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
} DATA_FLAGS;

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

	ULONG64     NtDeviceIoControlFile;          // offset 224
	ULONG64     ArmNtDeviceIoControlFile;      // for ARM64 // offset 232
	ULONG64     NtProtectVirtualMemory;       // offset 240
	ULONG64     NtRaiseHardError;             // offset 248

	ULONG64     SystemService;

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

extern ULONG* __SyscallsData;
ULONG QuerySyscalls(BOOLEAN IsDriver);


