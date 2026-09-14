#pragma once
#include "Common.h"


void WINAPI ServiceMain(DWORD argc, WCHAR* argv[]);




extern HMODULE  __Ntdll;
extern HMODULE  __Kernel32;

extern ULONG    __Windows;   //??????

extern SYSTEM_INFO __SystemInfo;