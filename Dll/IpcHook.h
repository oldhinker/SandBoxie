#pragma once
#include "Common.h"
#include "ObjectHelper.h"
#include "IpcHelper.h"

BOOLEAN IpcHook(void);



NTSTATUS DetourNtCreatePort(
    HANDLE* PortHandle,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    ULONG MaxConnectInfoLength,
    ULONG MaxDataLength,
    ULONG* Reserved);

NTSTATUS DetourNtConnectPort(
    HANDLE* PortHandle,
    UNICODE_STRING* PortName,
    SECURITY_QUALITY_OF_SERVICE* SecurityQos,
    void* ClientSharedMemory,
    void* ServerSharedMemory,
    ULONG* MaximumMessageLength,
    void* ConnectionInfo,
    ULONG* ConnectionInfoLength);

NTSTATUS DetourNtSecureConnectPort(
    HANDLE* PortHandle,
    UNICODE_STRING* PortName,
    SECURITY_QUALITY_OF_SERVICE* SecurityQos,
    void* ClientSharedMemory,
    PSID ServerSid,
    void* ServerSharedMemory,
    ULONG* MaximumMessageLength,
    void* ConnectionInfo,
    ULONG* ConnectionInfoLength);


NTSTATUS DetourNtAlpcCreatePort(
    HANDLE* PortHandle,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    void* AlpcCreateInfo);


NTSTATUS DetourNtAlpcConnectPort(
    HANDLE* PortHandle,
    UNICODE_STRING* PortName,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    ALPC_PORT_ATTRIBUTES* AlpcConnectInfo,
    ULONG ConnectionFlags,
    PSID ServerSid,
    void* ConnectionInfo,
    ULONG* ConnectionInfoLength,
    void* InMessageBuffer,
    void* OutMessageBuffer,
    LARGE_INTEGER* Timeout);


NTSTATUS DetourNtAlpcConnectPortEx(
    HANDLE* PortHandle,
    OBJECT_ATTRIBUTES* ObjectAttributes1,
    OBJECT_ATTRIBUTES* ObjectAttributes2,
    ALPC_PORT_ATTRIBUTES* AlpcConnectInfo,
    ULONG ConnectionFlags,
    SECURITY_DESCRIPTOR* ServerSd,
    void* ConnectionInfo,
    ULONG* ConnectionInfoLength,
    void* InMessageBuffer,
    void* OutMessageBuffer,
    LARGE_INTEGER* Timeout);


NTSTATUS DetourNtAlpcQueryInformation(
    HANDLE* PortHandle,
    ULONG InformationClass,
    void* Information,
    ULONG InformationLength,
    ULONG_PTR UnknownParameter5);


NTSTATUS DetourNtAlpcQueryInformationMessage(
    HANDLE* PortHandle,
    void* RpcMessage,
    ULONG InformationClass,
    void* Information,
    ULONG InformationLength,
    ULONG_PTR UnknownParameter6);


void DetourCreateObjects(void);