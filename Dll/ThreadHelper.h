#pragma once
#include "Common.h"

#define TRUE_NAME_BUFFER        0
#define COPY_NAME_BUFFER        1
#define TMPL_NAME_BUFFER        2
#define NORM_NAME_BUFFER        3
#define MISC_NAME_BUFFER        4 // 5 - 11

#define NAME_BUFFER_COUNT       12
#define NAME_BUFFER_DEPTH       16
typedef struct _THREAD_DATA
{

    WCHAR* BufferData[NAME_BUFFER_COUNT][NAME_BUFFER_DEPTH];
    ULONG DataLength[NAME_BUFFER_COUNT][NAME_BUFFER_DEPTH];
    int BufferDepth;
    ULONG_PTR       v1;
    BOOLEAN         NtQueryObjectLock;

}THREAD_DATA;
THREAD_DATA* GetTlsData(ULONG* LastError);

extern ULONG __TlsIndex;




#ifdef NAME_BUFFER_DEBUG
#else
WCHAR* GetTlsNameBuffer(THREAD_DATA* ThreadData, ULONG Which, ULONG ViewSize);
#endif