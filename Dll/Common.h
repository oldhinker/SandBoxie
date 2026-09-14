#pragma once
#include <Windows.h>
#include <iostream>
#include <tchar.h>
using namespace std;

#define _BOXED_              L"_BOXED_"
#define _BOXED_LENGTH_           (7)


#define BOX_NAME			(38 + 2)


#define DEVICE_NAME         L"\\Device\\KSandBox"


extern "C" void Interrupt();