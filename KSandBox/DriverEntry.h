#pragma once
#include "Common.h"



void DriverUnload(PDRIVER_OBJECT DriverObject);


extern PDRIVER_OBJECT  __DriverObject;
extern volatile BOOLEAN __ReadyToSandbox;
extern WCHAR* __DriverVersion;
extern volatile BOOLEAN __IsDriverUnloading;



const WCHAR* __S_1_5_18 ; //	System
const WCHAR* __S_1_5_19 ; //	Local Service
const WCHAR* __S_1_5_20 ; //	Network Service