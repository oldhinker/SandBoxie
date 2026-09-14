#pragma once
#include "Common.h"


extern HMODULE  __Ntdll;
extern ULONG    __Windows;
extern ULONG __ProcessIdentity;
extern const WCHAR* __BoxIpcPathData;
extern ULONG __BoxIpcPathLength;


void InitializeGeneric(HINSTANCE Instance);