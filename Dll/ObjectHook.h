#pragma once
#include "Common.h"
#include "ObjectHelper.h"






BOOLEAN ObjectHook(void);

NTSTATUS DetourNtQueryObject(
    HANDLE ObjectHandle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    void* ObjectInformation,
    ULONG Length,
    ULONG* ResultLength);

ULONG DetourGetObjectType(HANDLE ObjectHandle);
NTSTATUS  DetourNtCreateEvent(
    HANDLE* EventHandle,
    ACCESS_MASK DesiredAccess,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    EVENT_TYPE EventType,
    BOOLEAN InitialState);

NTSTATUS DetourNtOpenEvent(
    HANDLE* EventHandle,
    ACCESS_MASK DesiredAccess,
    OBJECT_ATTRIBUTES* ObjectAttributes);

NTSTATUS DetourNtOpenDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS DetourNtCreateDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

extern LPFN_NTQUERYOBJECT          __sys_NtQueryObject;
extern LPFN_NTCREATEEVENT          __sys_NtCreateEvent;
extern LPFN_NTOPENEVENT            __sys_NtOpenEvent;
extern LPFN_NTCREATEDIRECTORYOBJECT    __sys_NtCreateDirectoryObject;
extern LPFN_NTOPENDIRECTORYOBJECT      __sys_NtOpenDirectoryObject;