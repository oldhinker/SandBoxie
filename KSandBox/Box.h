#pragma once
#include "Common.h"
#include "MemoryPool.h"



typedef struct _BOX_             BOX;


struct _BOX_ {

    // a sandbox is identified by three components:
    // 1.  the name of this box

    WCHAR BoxName[BOX_NAME];
    ULONG NameLength;


    // 3.  Terminal Services session number

    ULONG SessionIdentity;



    // 3.  the based named objects directory for the sandbox
  // default:  \Sandbox\%SID%\Session_%SESSION%\BoxName

    WCHAR* IpcPath;
    ULONG  IpcLength;                 // in bytes, including NULL
};

BOX* CreateBox(
    POOL* Pool, const WCHAR* BoxName,
    const WCHAR* SidString, ULONG SessionIdentity,
    BOOLEAN IsInitializePaths);

BOX* CreateBoxInternal(POOL* Pool, const WCHAR* BoxName, ULONG SessionIdentity);

BOX* CloneBox(POOL* Pool, const BOX* Box);

BOX* AllocateBox(POOL* Pool, const WCHAR* BoxName, ULONG SessionIdentity);
void FreeBox(BOX* Box);



NTSTATUS CopyBoxPathsToUser(
    BOX* Box, ULONG* FileLength, ULONG* KeyLength, ULONG* IpcLength,
    UNICODE_STRING64* FilePath,
    UNICODE_STRING64* KeyPath,
    UNICODE_STRING64* IpcPath);