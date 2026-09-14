#pragma once
#include "Common.h"
#include "MemoryList.h"

typedef struct _DLL_ENTRY_ DLL_ENTRY, *PDLL_ENTRY;


struct _DLL_ENTRY_ {

    NODE  Node;
    WCHAR DllName[32];   
    HANDLE FileHandle;
    HANDLE SectionHandle;
    ULONG_PTR ImageBase;
    ULONG SizeOfImage;
    UCHAR* MappingBase;    //代码申请内存
    IMAGE_NT_HEADERS* ImageNtHeaders;
    IMAGE_EXPORT_DIRECTORY* ImageExportDirectory;      //文件粒度对齐的数据 

};

BOOLEAN InitializeDll(void);
void UninitializeDll(void);
DLL_ENTRY* LoadDll(const WCHAR* DllName);

void* RvaToFoa(DLL_ENTRY* DllEntry, ULONG Rva);


ULONG GetProcAddress(
    DLL_ENTRY* DllEntry, const UCHAR* SearchName,   //zw
    UCHAR** FoundName, ULONG* FoundIndex);

ULONG GetServiceIndex(UCHAR* ServiceAddress);
extern const WCHAR* __Ntdll;