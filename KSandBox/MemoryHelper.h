#pragma once
#include "Common.h"
#include "MemoryPool.h"
#define MemoryZero(VirtualAddress,ViewSize)        memset((VirtualAddress),0,(ViewSize))


void* AllocateMemory(ULONG ViewSize, ULONG Tag);
void FreeMemory(void* VirtualAddress, ULONG Tag);



void* AllocateMemoryEx(POOL* Pool, ULONG ViewSize, BOOLEAN Tag);
void FreeMemoryEx(void* VirtualAddress, ULONG ViewSize);


WCHAR* AllocateStringEx(
    POOL* Pool, const WCHAR* StringData, BOOLEAN Tag);


void CopyStringToUser(
    UNICODE_STRING64* StringData, WCHAR* BufferData, size_t DataLength);