#pragma once
#include "Common.h"





#ifndef NT_SUCCESS
#define NT_SUCCESS(StatCode)  ((NTSTATUS)(StatCode) >= 0)
#endif


typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;   
        PVOID Pointer;
    };
    ULONG_PTR Information;  
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;