#pragma once
#include "Common.h"
#include "ApiHelper.h"


#define DRIVER_VERSION  0x57010

#define	WINDOWS_XP       2
#define	WINDOWS_2003     3
#define	WINDOWS_VISTA    4
#define	WINDOWS_7        5
#define	WINDOWS_8        6
#define	WINDOWS_81       7
#define	WINDOWS_10       8


extern ULONG __OsVersion;
extern ULONG __OsBuild;
extern WCHAR* __HomePath2;   //DosPath      //ƒ⁄¥Ê…Í«Î
extern WCHAR* __HomePath1;   //NtPah        //ƒ⁄¥Ê…Í«Î

BOOLEAN CheckOsVersion(void);
ULONG_PTR GetNtosKrnl(void);
BOOLEAN CheckHomePath(UNICODE_STRING* RegistryPath);

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     LoadOrder;
    LIST_ENTRY     MemoryOrder;
    LIST_ENTRY     InitializationOrder;
    PVOID          ModuleBaseAddress;
    PVOID          EntryPoint;
    ULONG          ModuleSize;
    UNICODE_STRING FullModuleName;
    UNICODE_STRING ModuleName;
    ULONG          Flags;
    USHORT         LoadCount;
    USHORT         TlsIndex;
    union {
        LIST_ENTRY Hash;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    ULONG   TimeStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
#if !defined PO_CB_SYSTEM_POWER_POLICY
    SystemPowerInformation,
#else
    _SystemPowerInformation,
#endif
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS;

NTSYSAPI NTSTATUS NTAPI   ZwQuerySystemInformation(
    IN  SYSTEM_INFORMATION_CLASS    SystemInformationClass,
    OUT PVOID                       SystemInformation,
    IN  ULONG                       SystemInformationLength,
    OUT PULONG                      ReturnLength OPTIONAL);





typedef struct _SYSTEM_MODULE_ENTRY {
    ULONG_PTR   Reserved1;
    ULONG_PTR   MappedBase;
    ULONG_PTR   ImageBaseAddress;
    ULONG       ImageSize;
    ULONG       Flags;
    USHORT      LoadCount;
    USHORT      LoadOrderIndex;
    USHORT      InitOrderIndex;
    USHORT      NameOffset;
    UCHAR       Path[256];
} SYSTEM_MODULE_ENTRY;



typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG       ModuleCount;
#ifdef _WIN64
    ULONG       Reserved;
#endif
    SYSTEM_MODULE_ENTRY  SystemModuleEntry[0];
} SYSTEM_MODULE_INFORMATION;




BOOLEAN InitializeSyscalls();





