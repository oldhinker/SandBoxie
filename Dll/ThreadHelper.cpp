#include "ThreadHelper.h"
#include "MemoryPool.h"

ULONG __TlsIndex = TLS_OUT_OF_INDEXES;

THREAD_DATA* GetTlsData(ULONG* LastError)
{
    THREAD_DATA* ThreadData;

    if (__TlsIndex == TLS_OUT_OF_INDEXES)
        ThreadData = NULL;
    else {

        ULONG v1 = GetLastError();

        ThreadData = (THREAD_DATA*)TlsGetValue(__TlsIndex);

        if (!ThreadData) {

            ThreadData = (THREAD_DATA*)MemoryPoolAllocateEx(__Pool10, sizeof(THREAD_DATA));
            ZeroMemory(ThreadData, sizeof(THREAD_DATA));

            TlsSetValue(__TlsIndex, ThreadData);
        }

        SetLastError(v1);
        if (LastError)
            *LastError = v1;
    }

    return ThreadData;
}


#ifdef NAME_BUFFER_DEBUG
WCHAR* GetTlsNameBuffer(THREAD_DATA* ThreadData, ULONG Which, ULONG ViewSize, char* func)
#else
WCHAR* GetTlsNameBuffer(THREAD_DATA* ThreadData, ULONG Which, ULONG ViewSize)
#endif
{
    WCHAR* v1;   
    ULONG v2;     //原始内存
    WCHAR** v5;
    ULONG* v7;

    //
    // since we have more places where we may need a name buffer now
    // instead of sticking to "which" and doing our best to not reuse a particular buffer that's still needed
    // we just increment a counter and take a new buffer reach time we request one
    //

    /*
    if (Which >= MISC_NAME_BUFFER)
        Which = MISC_NAME_BUFFER + data->name_buffer_count[data->name_buffer_depth]++;

#ifdef NAME_BUFFER_DEBUG
    DbgTrace("Dll_GetTlsNameBuffer, %s, %d\r\n", func, which);
#endif

    if (which >= NAME_BUFFER_COUNT - 2)
        SbieApi_Log(2310, L"%d", which);
    if (which >= NAME_BUFFER_COUNT) {
        ExitProcess(-1);
    }*/

    v5 = &ThreadData->BufferData[Which][ThreadData->BufferDepth];
    v7 = &ThreadData->DataLength[Which][ThreadData->BufferDepth];

    //
    // round up the requested size (+ extra padding of some bytes)
    // to a multiple of PAGE_SIZE.
    //

    //ViewSize = (ViewSize + 64 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);   ????????????????????????????
    if (ViewSize > *v7) {

        //
        // requested size is larger than current name buffer, so we
        // allocate a larger buffer, and move the contents over to it
        //

        v1 = *v5;
        v2 = *v7;

        *v7 = ViewSize;
        *v5 = (WCHAR*)MemoryPoolAllocateEx(__Pool10,*v7);    //重新申请内存

        if (v1) {
            memcpy(*v5, v1, v2);
            MemoryPoolFreeEx(v1);
        }
    }

    //
    // debug checks:  the name buffer is allocated at least 64 bytes
    // more than needed.  fill these with 0xCC, and check that later
    //

#ifdef DEBUG_MEMORY

    {
        UCHAR* v10 = ((UCHAR*)(*v5)) + *v7 - 64;
        memset(v10, 0xCC, 64);
    }

#endif // DEBUG_MEMORY

    return *v5;
}
