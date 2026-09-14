#pragma once
#include "Common.h"


#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )


typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID* PCLIENT_ID;