#pragma once
#include "Common.h"
#include "MemoryPool.h"

#define PAD_LEN         (4 * sizeof(WCHAR))

typedef struct _OBJECT_DUMP_CONTROL {
    PVOID Stream;
    ULONG Detail;
} OB_DUMP_CONTROL, * POB_DUMP_CONTROL;


typedef enum _OB_OPEN_REASON {
    ObCreateHandle,
    ObOpenHandle,
    ObDuplicateHandle,
    ObInheritHandle,
    ObMaxOpenReason
} OB_OPEN_REASON;

typedef VOID(*OB_DUMP_METHOD)(
    IN PVOID Object,
    IN POB_DUMP_CONTROL Control OPTIONAL);


typedef NTSTATUS(*OB_OPEN_METHOD)(
    IN OB_OPEN_REASON OpenReason,
    IN PEPROCESS Process OPTIONAL,
    IN PVOID Object,
    IN ACCESS_MASK GrantedAccess,
    IN ULONG HandleCount);


typedef NTSTATUS(*OB_OPEN_METHOD_VISTA)(
    IN OB_OPEN_REASON OpenReason,
    IN ACCESS_MASK GrantedAccess,
    IN PEPROCESS Process OPTIONAL,
    IN PVOID Object,
    PVOID Unknown1,
    IN ULONG HandleCount);


typedef VOID(*OB_CLOSE_METHOD)(
    IN PEPROCESS Process OPTIONAL,
    IN PVOID Object,
    IN ACCESS_MASK GrantedAccess,
    IN ULONG ProcessHandleCount,
    IN ULONG SystemHandleCount);


typedef VOID(*OB_DELETE_METHOD)(
    IN PVOID Object);


typedef NTSTATUS(*OB_PARSE_METHOD)(
    IN PVOID ParseObject,
    IN PVOID ObjectType,
    IN OUT PACCESS_STATE AccessState,
    IN KPROCESSOR_MODE AccessMode,
    IN ULONG Attributes,
    IN OUT PUNICODE_STRING CompleteName,
    IN OUT PUNICODE_STRING RemainingName,
    IN OUT PVOID Context OPTIONAL,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
    OUT PVOID* Object);


typedef NTSTATUS(*OB_SECURITY_METHOD)(
    IN PVOID Object,
    IN SECURITY_OPERATION_CODE OperationCode,
    IN PSECURITY_INFORMATION SecurityInformation,
    IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN OUT PULONG CapturedLength,
    IN OUT PSECURITY_DESCRIPTOR* ObjectsSecurityDescriptor,
    IN POOL_TYPE PoolType,
    IN PGENERIC_MAPPING GenericMapping);


typedef NTSTATUS(*OB_QUERYNAME_METHOD)(
    IN PVOID Object,
    IN BOOLEAN HasObjectName,
    OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
    IN ULONG Length,
    OUT PULONG ReturnLength);


typedef BOOLEAN(*OB_OKAYTOCLOSE_METHOD)(
    IN PEPROCESS Process OPTIONAL,
    IN PVOID Object,
    IN HANDLE Handle);


typedef struct _OBJECT_TYPE_INITIALIZER {
    USHORT Length;
    BOOLEAN UseDefaultObject;
    BOOLEAN Reserved;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    BOOLEAN MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    OB_DUMP_METHOD DumpProcedure;
    OB_OPEN_METHOD OpenProcedure;
    OB_CLOSE_METHOD CloseProcedure;
    OB_DELETE_METHOD DeleteProcedure;
    OB_PARSE_METHOD ParseProcedure;
    OB_SECURITY_METHOD SecurityProcedure;
    OB_QUERYNAME_METHOD QueryNameProcedure;
    OB_OKAYTOCLOSE_METHOD OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE {
    //ERESOURCE Mutex;              // not present in 7 or later was that in xp?
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;            // Copy from object header for convenience
    PVOID DefaultObject;
    ULONG Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER TypeInfo;
} OBJECT_TYPE, * POBJECT_TYPE;


typedef struct _OBJECT_TYPE_INITIALIZER_VISTA_SP1 {
    USHORT Length;
    BOOLEAN ObjectTypeFlags;
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG RetainAccess;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    OB_DUMP_METHOD DumpProcedure;
    OB_OPEN_METHOD OpenProcedure;
    OB_CLOSE_METHOD CloseProcedure;
    OB_DELETE_METHOD DeleteProcedure;
    OB_PARSE_METHOD ParseProcedure;
    OB_SECURITY_METHOD SecurityProcedure;
    OB_QUERYNAME_METHOD QueryNameProcedure;
    OB_OKAYTOCLOSE_METHOD OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER_VISTA_SP1, * POBJECT_TYPE_INITIALIZER_VISTA_SP1;


typedef struct _OBJECT_TYPE_VISTA_SP1 {
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;            // Copy from object header for convenience
    PVOID DefaultObject;
    ULONG Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER_VISTA_SP1 TypeInfo;
    ERESOURCE Mutex;
    EX_PUSH_LOCK TypeLock;
    ULONG Key;
    EX_PUSH_LOCK ObjectLocks[32];
    LIST_ENTRY CallbackList;
} OBJECT_TYPE_VISTA_SP1, * POBJECT_TYPE_VISTA_SP1;


NTSTATUS
NTAPI
ObOpenObjectByName(IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN POBJECT_TYPE ObjectType,
    IN KPROCESSOR_MODE AccessMode,
    IN PACCESS_STATE PassedAccessState,
    IN ACCESS_MASK DesiredAccess,
    IN OUT PVOID ParseContext,
    OUT PHANDLE Handle);




typedef ULONG(*LPFN_OBQUERYNAMEINFO)(void* Object);   //数据类型
typedef void* (*LPFN_OBGETOBJECTTYPE)(void* Object);

BOOLEAN InitializeObject(void);


BOOLEAN GetObjectTypeEx(const WCHAR* TypeName);
OBJECT_TYPE* GetObjectType(const WCHAR* TypeName);
POBJECT_TYPE GetTypeObjectType(void);

NTSTATUS GetObjectName(
    POOL* Pool, void* Object,
    OBJECT_NAME_INFORMATION** ObjectNameInfo, ULONG* NameLength);

extern LPFN_OBQUERYNAMEINFO __ObQueryNameInfo;
extern LPFN_OBGETOBJECTTYPE __ObGetObjectType;
extern POBJECT_TYPE* LpcPortObjectType;   


extern const OBJECT_NAME_INFORMATION __UnnamedObject;