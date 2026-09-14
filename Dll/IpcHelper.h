#pragma once
#include "Common.h"
#include "StringHelper.h"
#include "ObjectHelper.h"



typedef NTSTATUS(*LPFN_NTCREATEPORT)(
    OUT PHANDLE PortHandle,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  ULONG MaxConnectInfoLength,
    IN  ULONG MaxDataLength,
    IN  OUT PULONG Reserved OPTIONAL);

typedef NTSTATUS(*LPFN_NTCONNECTPORT)(
    OUT PHANDLE ClientPortHandle,
    IN  PUNICODE_STRING ServerPortName,
    IN  PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    IN  OUT void* ClientSharedMemory OPTIONAL,
    OUT void* ServerSharedMemory OPTIONAL,
    OUT PULONG MaximumMessageLength OPTIONAL,
    IN  OUT PVOID ConnectionInfo OPTIONAL,
    IN  OUT PULONG ConnectionInfoLength OPTIONAL);

typedef NTSTATUS(*LPFN_NTSECURECONNECTPORT)(
    OUT PHANDLE ClientPortHandle,
    IN  PUNICODE_STRING ServerPortName,
    IN  PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    IN  OUT void* ClientSharedMemory OPTIONAL,
    IN  PSID ServerSid OPTIONAL,
    OUT void* ServerSharedMemory OPTIONAL,
    OUT PULONG MaximumMessageLength OPTIONAL,
    IN  OUT PVOID ConnectionInfo OPTIONAL,
    IN  OUT PULONG ConnectionInfoLength OPTIONAL);

typedef NTSTATUS(*LFPN_NTALPCCREATEPORT)(
    OUT PHANDLE ServerPortHandle,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  OUT void* PortInformation OPTIONAL);


typedef NTSTATUS(*LPFN_NTALPCCONNECTPORT)(
    OUT PHANDLE ClientPortHandle,
    IN  PUNICODE_STRING ServerPortName,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  void* AlpcPortAttributes OPTIONAL,
    IN  ULONG ConnectionFlags,
    IN  PSID ServerSid OPTIONAL,
    IN  OUT PVOID ConnectionInfo OPTIONAL,
    IN  OUT PULONG ConnectionInfoLength OPTIONAL,
    IN  PVOID InMessageBuffer OPTIONAL,
    IN  PVOID OutMessageBuffer OPTIONAL,
    IN  PLARGE_INTEGER Timeout OPTIONAL);

typedef NTSTATUS(*LPFN_NTALPCCONNECTPORTEX)(
    OUT PHANDLE ClientPortHandle,
    IN  POBJECT_ATTRIBUTES ObjectAttributes1,
    IN  POBJECT_ATTRIBUTES ObjectAttributes2,
    IN  void* AlpcPortAttributes OPTIONAL,
    IN  ULONG ConnectionFlags,
    IN  PSECURITY_DESCRIPTOR ServerSd OPTIONAL,
    IN  OUT PVOID ConnectionInfo OPTIONAL,
    IN  OUT PULONG ConnectionInfoLength OPTIONAL,
    IN  PVOID InMessageBuffer OPTIONAL,
    IN  PVOID OutMessageBuffer OPTIONAL,
    IN  PLARGE_INTEGER Timeout OPTIONAL);


typedef NTSTATUS(*LPFN_NTALPCQUERYINFORMATION)(
    IN  PHANDLE PortHandle,
    IN  ULONG InformationClass,
    IN  OUT PVOID Information,
    IN  ULONG InformationLength,
    IN  ULONG_PTR UnknownParameter5);

typedef NTSTATUS(*LPFN_NTALPCQUERYINFORMATIONMESSAGE)(
    IN  PHANDLE PortHandle,
    IN  void* RpcMessage,
    IN  ULONG InformationClass,
    IN  OUT PVOID Information,
    IN  ULONG InformationLength,
    IN  ULONG_PTR UnknownParameter6);



typedef struct _ALPC_PORT_ATTRIBUTES {

    ULONG       Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    ULONG       MaxMessageLength;
    ULONG_PTR   MemoryBandwidth;
    ULONG_PTR   MaxPoolUsage;
    ULONG_PTR   MaxSectionSize;
    ULONG_PTR   MaxViewSize;
    ULONG_PTR   MaxTotalSectionSize;
    ULONG_PTR   DupObjectTypes;

} ALPC_PORT_ATTRIBUTES;



#ifdef __cplusplus
extern "C" {
#endif
    __declspec(dllimport) NTSTATUS __stdcall
        NtCreatePort(
            OUT PHANDLE PortHandle,
            IN  POBJECT_ATTRIBUTES ObjectAttributes,
            IN  ULONG MaxConnectInfoLength,
            IN  ULONG MaxMsgLength,
            IN  OUT PULONG Reserved OPTIONAL);
    __declspec(dllimport)
        NTSTATUS __stdcall
        NtConnectPort(
            OUT PHANDLE ClientPortHandle,
            IN  PUNICODE_STRING ServerPortName,
            IN  PSECURITY_QUALITY_OF_SERVICE SecurityQos,
            IN  OUT void* ClientSharedMemory OPTIONAL,
            OUT void* ServerSharedMemory OPTIONAL,
            OUT PULONG MaximumMessageLength OPTIONAL,
            IN  OUT PVOID ConnectionInfo OPTIONAL,
            IN  OUT PULONG ConnectionInfoLength OPTIONAL);

    __declspec(dllimport) NTSTATUS __stdcall
        NtSecureConnectPort(
            OUT PHANDLE ClientPortHandle,
            IN  PUNICODE_STRING ServerPortName,
            IN  PSECURITY_QUALITY_OF_SERVICE SecurityQos,
            IN  OUT  void* ClientSharedMemory OPTIONAL,
            IN  PSID ServerSid OPTIONAL,
            OUT  void* ServerSharedMemory OPTIONAL,
            OUT PULONG MaximumMessageLength OPTIONAL,
            IN  OUT PVOID ConnectionInfo OPTIONAL,
            IN  OUT PULONG ConnectionInfoLength OPTIONAL);

#ifdef __cplusplus
}
#endif

