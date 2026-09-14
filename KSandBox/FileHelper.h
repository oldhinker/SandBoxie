#pragma once
#include "Common.h"
#include "MemoryPool.h"
NTSTATUS TranslateDosToNt(
    const WCHAR* InPath, WCHAR** OutPath, ULONG* PathLength);

NTSTATUS TranslateDosToNtInternal(
    const WCHAR* InPath, POOL* Pool, WCHAR** OutPath, ULONG* PathLength);


NTSTATUS TranslateShares(
    const WCHAR* InPath, POOL* Pool, WCHAR** OutPath, ULONG* PathLength);

NTSTATUS TranslateSymlinks(WCHAR* BufferData, ULONG DataLength);


BOOLEAN InitializeFile(void);
