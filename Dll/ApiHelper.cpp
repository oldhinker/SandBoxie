#include "ApiHelper.h"
#include "StatusHelper.h"
#include "IoRequest.h"

LONG QueryProcessEx(
    HANDLE ProcessIdentity,
    ULONG  NameLength,
    WCHAR* BoxName,
    WCHAR* ImageName,
    WCHAR* SidString,
    ULONG* SessionIdentity,
    ULONG64* CreateTime)
{
    NTSTATUS Status;
    __declspec(align(8)) UNICODE_STRING64 v1;
    __declspec(align(8)) UNICODE_STRING64 v2;
    __declspec(align(8)) UNICODE_STRING64 v3;
    __declspec(align(8)) ULONG64 ParameterData[API_NUMBER_ARGS];
    QUERY_PROCESS_ARGS* Arguments = (QUERY_PROCESS_ARGS*)ParameterData;

    ZeroMemory(ParameterData, sizeof(ParameterData));
    Arguments->ServiceIndex = QUERY_PROCESS;

    Arguments->ProcessIdentity.Value64 = (ULONG64)(ULONG_PTR)ProcessIdentity;

    if (BoxName) {
        v1.Length = 0;
        v1.MaximumLength = (USHORT)(sizeof(WCHAR) * BOX_NAME);
        v1.Buffer = (ULONG64)(ULONG_PTR)BoxName;
        Arguments->BoxName.Value64 = (ULONG64)(ULONG_PTR)&v1;
    }

    if (ImageName) {
        v2.Length = 0;
        v2.MaximumLength =
            (USHORT)(sizeof(WCHAR) * NameLength);
        v2.Buffer = (ULONG64)(ULONG_PTR)ImageName;
        Arguments->ImageName.Value64 = (ULONG64)(ULONG_PTR)&v2;
    }

    if (SidString) {
        v3.Length = 0;
        v3.MaximumLength = (USHORT)(sizeof(WCHAR) * 96);
        v3.Buffer = (ULONG64)(ULONG_PTR)SidString;
        Arguments->SidString.Value64 = (ULONG64)(ULONG_PTR)&v3;
    }

    if (SessionIdentity)
        Arguments->SessionIdentity.Value64 = (ULONG64)(ULONG_PTR)SessionIdentity;

    if (CreateTime)
        Arguments->CreateTime.Value64 = (ULONG64)(ULONG_PTR)CreateTime;

    Status = IoctlRequest(ParameterData);

    if (!NT_SUCCESS(Status)) {

        ULONG_PTR x = (ULONG_PTR)SessionIdentity;
        if (x == 0 || x > 4) {

            //
            // reset parameters on error except when out_session_id
            // is a special internal flag in the range 1 to 4
            //

            if (BoxName)
                *BoxName = L'\0';
            if (ImageName)
                *ImageName = L'\0';
            if (SidString)
                *SidString = L'\0';
            if (SessionIdentity)
                *SessionIdentity = 0;
        }
    }

    return Status;
}


LONG QueryDriverInfo(ULONG InfoClass, VOID* BufferData, ULONG DataLength)
{
    NTSTATUS Status;
    __declspec(align(8)) ULONG64 ParameterData[API_NUMBER_ARGS];

    memset(ParameterData, 0, sizeof(ParameterData));
    ParameterData[0] = QUERY_DRIVER_INFO;
    ParameterData[1] = InfoClass;
    ParameterData[2] = (ULONG64)(ULONG_PTR)BufferData;
    ParameterData[3] = DataLength;
    Status = IoctlRequest(ParameterData);

    return Status;
}

ULONG64 QueryProcessInfoEx(
    HANDLE ProcessIdentity,
    ULONG  InfoType,
    ULONG64 BufferData)
{
    NTSTATUS Status;
    __declspec(align(8)) ULONG64 ResultValue;
    __declspec(align(8)) ULONG64 ParameterData[API_NUMBER_ARGS];
    API_QUERY_PROCESS_INFO_ARGS* Arguments = (API_QUERY_PROCESS_INFO_ARGS*)ParameterData;

    ZeroMemory(ParameterData, sizeof(ParameterData));
    Arguments->ServiceIndex = QUERY_PROCESS_INFO;

    Arguments->ProcessIdentity.Value64 = (ULONG64)(ULONG_PTR)ProcessIdentity;
    Arguments->InfoType.Value64 = (ULONG64)(ULONG_PTR)InfoType;
    Arguments->ResultValue.Value64 = (ULONG64)(ULONG_PTR)&ResultValue;
    Arguments->BufferData.Value64 = (ULONG64)(ULONG_PTR)BufferData;

    Status = IoctlRequest(ParameterData);

    if (!NT_SUCCESS(Status))
        ResultValue = 0;

    return ResultValue;
}
LONG QueryBoxPath(
    const WCHAR* BoxName,              // WCHAR [BOXNAME_COUNT]
    WCHAR* FilePath,
    WCHAR* KeyPath,
    WCHAR* IpcPath,
    ULONG* FileLength,
    ULONG* KeyLength,
    ULONG* IpcLength)
{
    NTSTATUS Status;
    __declspec(align(8)) UNICODE_STRING64 v1;
    __declspec(align(8)) UNICODE_STRING64 v2;
    __declspec(align(8)) UNICODE_STRING64 v3;
    __declspec(align(8)) ULONG64 ParameterData[API_NUMBER_ARGS];
    API_QUERY_BOX_PATH_ARGS* Arguments = (API_QUERY_BOX_PATH_ARGS*)ParameterData;

    ZeroMemory(ParameterData, sizeof(ParameterData));
    Arguments->ServiceIndex = QUERY_BOX_PATH;

    Arguments->BoxName.Value64 = (ULONG64)(ULONG_PTR)BoxName;

    if (FilePath)
    {
  
    }

    if (KeyPath) {
      
    }

    if (IpcPath) 
    {
        v3.Length = 0;
        v3.MaximumLength = (USHORT)*IpcLength;
        v3.Buffer = (ULONG64)(ULONG_PTR)IpcPath;
        Arguments->IpcPath.Value64 = (ULONG64)(ULONG_PTR)&v3;
    }

   
    Arguments->IpcLength.Value = IpcLength;

    Status = IoctlRequest(ParameterData);

    if (!NT_SUCCESS(Status)) {
     
        if (IpcPath)
            *IpcPath = L'\0';
    }

    return Status;
}

LONG EnumProcessEx(
    const WCHAR* BoxName,          // WCHAR [BOXNAME_COUNT]
    BOOLEAN IsAllSessions,
    ULONG WhichSession,            // -1 for current session
    ULONG* ProcessIdentitys,              // ULONG [512]
    ULONG* Count)
{
    NTSTATUS Status;
    __declspec(align(8)) ULONG64 ParameterData[API_NUMBER_ARGS];

    memset(ParameterData, 0, sizeof(ParameterData));
    ParameterData[0] = ENUM_PROCESSES;
    ParameterData[1] = (ULONG64)(ULONG_PTR)ProcessIdentitys;
    ParameterData[2] = (ULONG64)(ULONG_PTR)BoxName;
    ParameterData[3] = (ULONG64)(ULONG_PTR)IsAllSessions;
    ParameterData[4] = (ULONG64)(LONG_PTR)WhichSession;
    ParameterData[5] = (ULONG64)(LONG_PTR)Count;
    Status = IoctlRequest(ParameterData);

    if (!NT_SUCCESS(Status))
        ProcessIdentitys[0] = 0;

    return Status;
}


LONG GetFileName(
    HANDLE FileHandle,
    WCHAR* NameData,
    ULONG* DataLength,
    ULONG* ObjectType)
{
    NTSTATUS Status;
    __declspec(align(8)) ULONG64 ParameterData[API_NUMBER_ARGS];
    API_GET_FILE_NAME_ARGS* Arguments = (API_GET_FILE_NAME_ARGS*)ParameterData;

    memset(ParameterData, 0, sizeof(ParameterData));
    Arguments->ServiceIndex = GET_FILE_NAME;
    Arguments->FileHandle.Value64 = (ULONG64)(ULONG_PTR)FileHandle;
    Arguments->DataLength.Value64 = (ULONG64)(ULONG_PTR)DataLength;
    Arguments->NameData.Value64 = (ULONG64)(ULONG_PTR)NameData;
    Arguments->ObjectType.Value64 = (ULONG64)(ULONG_PTR)ObjectType;
    Status = IoctlRequest(ParameterData);

    if (!NT_SUCCESS(Status)) {
        if (NameData)
            *NameData = L'\0';
    }

    return Status;
}


LONG CreateDirOrLink(
    const WCHAR* ObjectName,
    const WCHAR* TargetName)
{
    NTSTATUS Status;
    __declspec(align(8)) UNICODE_STRING64 v1;
    __declspec(align(8)) UNICODE_STRING64 v2;
    __declspec(align(8)) ULONG64 ParameterData[API_NUMBER_ARGS];
    API_CREATE_DIR_OR_LINK_ARGS* Arguments =
        (API_CREATE_DIR_OR_LINK_ARGS*)ParameterData;

    v1.Length = wcslen(ObjectName) * sizeof(WCHAR);
    v1.MaximumLength = v1.Length + sizeof(WCHAR);
    v1.Buffer = (ULONG64)(ULONG_PTR)ObjectName;

    if (TargetName) {
        v2.Length = wcslen(TargetName) * sizeof(WCHAR);
        v2.MaximumLength = v2.Length + sizeof(WCHAR);
        v2.Buffer = (ULONG64)(ULONG_PTR)TargetName;
    }

    memset(ParameterData, 0, sizeof(ParameterData));
    Arguments->ServiceIndex = CREATE_DIR_OR_LINK;
    Arguments->ObjectName.Value64 = (ULONG64)(ULONG_PTR)&v1;
    if (TargetName)
        Arguments->TargetName.Value64 = (ULONG64)(ULONG_PTR)&v2;

    Status = IoctlRequest(ParameterData);

    return Status;
}
