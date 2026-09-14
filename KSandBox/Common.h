#pragma once
#include <fltKernel.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <wchar.h>
#include <string.h>

#define KERNEL_MODE

#define TAG    'GAT' 
#define DEVICE_NAME         L"\\Device\\KSandBox"
#define BOX_NAME			(38 + 2)


#ifndef SECONDS
#define SECONDS(n64)            (((LONGLONG)n64) * 10000000L)
#endif

#ifndef MINUTES
#define MINUTES(n64)            (SECONDS(n64) * 60)
#endif

#ifndef HOURS
#define HOURS(n64)              (MINUTES(n64) * 60)
#endif

#ifndef DAYS
#define DAYS(n64)               (HOURS(n64) * 24)
#endif



#define NTOS_API(Type)  NTSYSAPI Type NTAPI
#define NTOS_NTSTATUS   NTOS_API(NTSTATUS)
