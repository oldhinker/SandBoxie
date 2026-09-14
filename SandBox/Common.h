#pragma once
#include <Windows.h>
#include <iostream>
#include <tchar.h>

using namespace std;




#define DLL                 L"Dll"
#define NAME         L"SandBox"

#define INJECTION_SECTION ".text"
#define SYMBOL_SECTION     "xxxx"




#define DEVICE_NAME         L"\\Device\\KSandBox"



#define ULONG_DIFF(b,a) ((ULONG)((ULONG_PTR)(b) - (ULONG_PTR)(a)))