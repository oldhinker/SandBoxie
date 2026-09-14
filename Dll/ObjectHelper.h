#pragma once
#include "Common.h"
#include "StringHelper.h"



#ifdef  _WIN64
#pragma comment(lib,"..\\lib\\x64\\ntdll.lib")
#else
#pragma comment(lib,"..\\lib\\x86\\ntdll.lib")
#endif //  _WIN64



#define OBJECT_ATTRIBUTES_ATTRIBUTES                            \
    (ObjectAttributes                                           \
        ? ObjectAttributes->Attributes | OBJ_CASE_INSENSITIVE   \
        : 0)




typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllTypesInformation,
    ObjectDataInformation
} OBJECT_INFORMATION_CLASS;

enum {

    OBJ_TYPE_UNKNOWN,
    OBJ_TYPE_DIRECTORY,
    OBJ_TYPE_FILE,
    OBJ_TYPE_KEY,
    OBJ_TYPE_PORT,
    OBJ_TYPE_EVENT,
    OBJ_TYPE_MUTANT,
    OBJ_TYPE_SECTION,
    OBJ_TYPE_SEMAPHORE,
    OBJ_TYPE_PROCESS,
    OBJ_TYPE_LAST

};



#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct _PUBLIC_OBJECT_TYPE_INFORMATION {

    UNICODE_STRING TypeName;
    ULONG Reserved[22];    // reserved for internal use

} PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef enum _EVENT_TYPE { NotificationEvent, SynchronizationEvent } EVENT_TYPE;


#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)
#define DIRECTORY_CREATE_OBJECT         (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY   (0x0008)

#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

typedef NTSTATUS(*LPFN_NTQUERYOBJECT)(
    IN  HANDLE ObjectHandle,
    IN  OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN  ULONG Length,
    OUT PULONG ResultLength);

typedef NTSTATUS(*LPFN_NTCREATEEVENT)(
    OUT PHANDLE EventHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  EVENT_TYPE EventType,
    IN  BOOLEAN InitialState);

typedef NTSTATUS(*LPFN_NTOPENEVENT)(
    OUT PHANDLE EventHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(*LPFN_NTCREATEDIRECTORYOBJECT)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(*LPFN_NTOPENDIRECTORYOBJECT)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);
#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllimport) NTSTATUS __stdcall
NtQueryObject(
    IN HANDLE ObjectHandle OPTIONAL,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG Length,
    OUT PULONG ResultLength);


__declspec(dllimport) NTSTATUS __stdcall NtCreateEvent(
    OUT PHANDLE EventHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  EVENT_TYPE EventType,
    IN  BOOLEAN InitialState);

__declspec(dllimport) NTSTATUS __stdcall NtOpenEvent(
    OUT PHANDLE EventHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes);

__declspec(dllimport) NTSTATUS __stdcall
NtOpenDirectoryObject(
    OUT PHANDLE             DirectoryHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes
);

__declspec(dllimport) NTSTATUS __stdcall
NtCreateDirectoryObject(
    OUT PHANDLE             DirectoryHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes
);

__declspec(dllimport) NTSTATUS __stdcall
NtClose(
    IN HANDLE                       FileHandle);
#ifdef __cplusplus
}
#endif
NTSTATUS GetName(
    HANDLE RootDirectory, UNICODE_STRING* ObjectName,
    WCHAR** TruePath, WCHAR** CopyPath, BOOLEAN* IsBoxedPath);

NTSTATUS GetName2(
    OBJECT_ATTRIBUTES* ObjectAttributes,
    WCHAR** TruePath, WCHAR** CopyPath,
    const WCHAR* ServiceName);


NTSTATUS GetObjectName(
    HANDLE ObjectHandle, void* ObjectName, ULONG* Length);


NTSTATUS CreatePath(WCHAR* TruePath, WCHAR* CopyPath);
