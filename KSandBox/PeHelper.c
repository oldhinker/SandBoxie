#include "PeHelper.h"
#include "MemoryList.h"
#include "MemoryHelper.h"


const WCHAR* __NtosKernel = L"NTOSKRNL.exe";
const WCHAR* __Ntdll = L"NTDLL.dll";
const WCHAR* __Win32u = L"WIN32U.dll";
#ifdef XP_SUPPORT
const WCHAR* __User32 = L"USER32.dll";
#endif

static LIST _DllList;
static BOOLEAN _IsDllList;
BOOLEAN InitializeDll(void)
{
    InitializeList(&_DllList);
    _IsDllList = TRUE;

    if (!LoadDll(__Ntdll))
        return FALSE;
#ifdef XP_SUPPORT
    if (!LoadDll(__User32))
        return FALSE;
#endif

    return TRUE;
}
void UninitializeDll(void)
{
    PDLL_ENTRY v1;

    if (!_IsDllList)
        return;

    while (1) 
    {
        v1 = GetListHead(&_DllList);
        if (!v1)
            break;
        RemoveCurrent(&_DllList, v1);

        if (v1->MappingBase)
            ZwUnmapViewOfSection(NtCurrentProcess(), v1->MappingBase);
        if (v1->SectionHandle)
            ZwClose(v1->SectionHandle);
        if (v1->FileHandle)
            ZwClose(v1->FileHandle);
    }
}


DLL_ENTRY* LoadDll(const WCHAR* DllName)
{
    NTSTATUS Status;
    DLL_ENTRY* v1;
    WCHAR DllPath[128];
    UNICODE_STRING v2;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;    //请求完成后的结果
    FILE_STANDARD_INFORMATION FileStarndardInfo;
    IMAGE_DOS_HEADER* ImageDosHeader;
    IMAGE_DATA_DIRECTORY* ImageDataDirectory;
    ULONG LastError;
    SIZE_T MappingSize;

    //
    // if we already have a loaded dll instance, return that
    //

    v1 = GetListHead(&_DllList);
    while (v1) {
        if (_wcsicmp(v1->DllName, DllName) == 0)
            return v1;
        v1 = GetNextNode(v1);
    }

    //
    // otherwise we allocate a dll instance and attempt to initialize it.
    // if any error occurs during initialization, the return dll->base
    // and dll->exports will be null, and the instance should not be used
    //

    v1 = AllocateMemoryEx(__Pool, sizeof(DLL_ENTRY),FALSE);
    if (!v1) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        LastError = 0x11;
        goto Exit;
    }

    MemoryZero(v1, sizeof(DLL_ENTRY));
    wcscpy(v1->DllName, DllName);

    //
    // open the dll file and query its on-disk size
    //


    
    RtlStringCbPrintfW(DllPath, sizeof(DllPath), L"\\SystemRoot\\System32\\%s", DllName);  //wchar []

    RtlInitUnicodeString(&v2, DllPath);
    InitializeObjectAttributes(
        &ObjectAttributes, &v2, OBJ_CASE_INSENSITIVE, NULL, NULL);


    //根据文件路径获取文件句柄
    Status = ZwCreateFile(
        &v1->FileHandle, FILE_GENERIC_READ, &ObjectAttributes, &IoStatusBlock, NULL,
        0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (!NT_SUCCESS(Status)) {
        v1->FileHandle = NULL;
        LastError = 0x12;
        goto Exit;
    }

    //根据文件句柄获取文件大小
    Status = ZwQueryInformationFile(
        v1->FileHandle, &IoStatusBlock, &FileStarndardInfo,
        sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
    if (!NT_SUCCESS(Status)) {
        LastError = 0x13;
        goto Exit;
    }

    // create and map the dll according to its on-disk size


    //文件映射 数据量大的时候

    //根据文件大小创建映射句柄
    Status = ZwCreateSection(
        &v1->SectionHandle, SECTION_MAP_READ | SECTION_QUERY, NULL,
        &FileStarndardInfo.EndOfFile, PAGE_READONLY, SEC_RESERVE, v1->FileHandle);
    if (!NT_SUCCESS(Status))
    {
        v1->SectionHandle = NULL;
        LastError = 0x14;
        goto Exit;
    }

    v1->MappingBase = NULL;
    MappingSize = (SIZE_T)FileStarndardInfo.EndOfFile.QuadPart;

    //根据映射句柄获取虚拟地址
    Status = ZwMapViewOfSection(
        v1->SectionHandle, NtCurrentProcess(), &v1->MappingBase, 0, 0, 0,
        &MappingSize, ViewUnmap, 0, PAGE_READONLY);
    if (!NT_SUCCESS(Status)) {
        v1->MappingBase = NULL;
        LastError = 0x15;
        goto Exit;
    }

    //
    // find the image exports directory in the mapped dll instance
    //

    ImageDataDirectory = NULL;

    ImageDosHeader = (IMAGE_DOS_HEADER*)v1->MappingBase;
    if (ImageDosHeader->e_magic == 'MZ' || ImageDosHeader->e_magic == 'ZM') 
    {

        IMAGE_NT_HEADERS* ImageNtHeaders =
            (IMAGE_NT_HEADERS*)((UCHAR*)ImageDosHeader + ImageDosHeader->e_lfanew);
        if (ImageNtHeaders->Signature == IMAGE_NT_SIGNATURE) {   // 'PE\0\0'

            v1->ImageNtHeaders = ImageNtHeaders;

            if (ImageNtHeaders->OptionalHeader.Magic ==
                IMAGE_NT_OPTIONAL_HDR32_MAGIC) {

                IMAGE_NT_HEADERS32* ImageNtHeader32 =
                    (IMAGE_NT_HEADERS32*)ImageNtHeaders;
                IMAGE_OPTIONAL_HEADER32* ImageOptionalHeader32 =
                    &ImageNtHeader32->OptionalHeader;
                ImageDataDirectory = &ImageOptionalHeader32->DataDirectory[0];

                v1->ImageBase = ImageOptionalHeader32->ImageBase;
                v1->SizeOfImage = ImageOptionalHeader32->SizeOfImage;

            }
            else if (ImageNtHeaders->OptionalHeader.Magic ==
                IMAGE_NT_OPTIONAL_HDR64_MAGIC) {

                IMAGE_NT_HEADERS64* ImageNtHeaders64 =
                    (IMAGE_NT_HEADERS64*)ImageNtHeaders;
                IMAGE_OPTIONAL_HEADER64* ImageOptionalHeader64 =
                    &ImageNtHeaders64->OptionalHeader;
                ImageDataDirectory = &ImageOptionalHeader64->DataDirectory[0];
                v1->ImageBase = (ULONG_PTR)ImageOptionalHeader64->ImageBase;
                v1->SizeOfImage = ImageOptionalHeader64->SizeOfImage;
            }
        }
    }

    if (!ImageDataDirectory) {
        Status = STATUS_UNSUCCESSFUL;
        LastError = 0x16;     // data_dirs still null, must be an invalid image
        goto Exit;
    }

    v1->ImageExportDirectory = (IMAGE_EXPORT_DIRECTORY*)RvaToFoa(
        v1, ImageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (!v1->ImageExportDirectory) {
        LastError = 0x17;     // could not translate rva to addr
        goto Exit;
    }

    //
    // finalize
    //

    InsertAfter(&_DllList, NULL, v1);
    LastError = 0;

Exit:
  
    if (LastError) 
    {
        if (v1->MappingBase)
            ZwUnmapViewOfSection(NtCurrentProcess(), v1->MappingBase);
        if (v1->SectionHandle)
            ZwClose(v1->SectionHandle);
        if (v1->FileHandle)
            ZwClose(v1->FileHandle);
        v1 = NULL;
    }



    return v1;
}
ULONG GetProcAddress(
    DLL_ENTRY* DllEntry, const UCHAR* SearchName,   //zw
    UCHAR** FoundName, ULONG* FoundIndex)
{


  
    ULONG* AddressOfNames = RvaToFoa(DllEntry, DllEntry->ImageExportDirectory->AddressOfNames);
    ULONG* AddressOfFunctions = RvaToFoa(DllEntry, DllEntry->ImageExportDirectory->AddressOfFunctions);
    USHORT* AddressOfNameOrdinals = RvaToFoa(DllEntry, DllEntry->ImageExportDirectory->AddressOfNameOrdinals);

    ULONG i;
    ULONG Offset = 0;
    UCHAR* ServiceName = NULL;

    if (AddressOfNames && AddressOfFunctions && AddressOfNameOrdinals) 
    {

        if (SearchName)
        {

            for (i = 0; i < DllEntry->ImageExportDirectory->NumberOfNames; ++i) 
            {

                ServiceName = RvaToFoa(DllEntry, AddressOfNames[i]);       //必须问ZwCreateProcess    CreateProcess  NtCreateProcess
                if (ServiceName && strcmp(ServiceName, SearchName) >= 0) {

                    Offset = AddressOfFunctions[AddressOfNameOrdinals[i]];
                    break;
                }
            }

            if (!Offset) {

                //日志记录
                //WCHAR v1[96];
                //RtlStringCbPrintfW(v1, sizeof(v1), L"%s.%S", DllEntry->DllName, SearchName);   //Ntll.dll   ZwCreatePrcess
              
            }

        }
        else {

            i = *FoundIndex + 1;
            if (i < DllEntry->ImageExportDirectory->NumberOfNames)
            {

                Offset = AddressOfFunctions[AddressOfNameOrdinals[i]];
                ServiceName = RvaToFoa(DllEntry, AddressOfNames[i]);
            }
        }

        *FoundName = ServiceName;
        *FoundIndex = i;
    }

    return Offset;
}




void* RvaToFoa(DLL_ENTRY* DllEntry, ULONG Rva)
{
    IMAGE_SECTION_HEADER* ImageSecitonHeader;
    ULONG i;

    ImageSecitonHeader = IMAGE_FIRST_SECTION(DllEntry->ImageNtHeaders);
    for (i = 0; i < DllEntry->ImageNtHeaders->FileHeader.NumberOfSections; ++i)
    {

        if (Rva >= ImageSecitonHeader->VirtualAddress &&
            Rva < ImageSecitonHeader->VirtualAddress + ImageSecitonHeader->SizeOfRawData)
        {

            void* Foa = DllEntry->MappingBase + Rva - ImageSecitonHeader->VirtualAddress + 
                ImageSecitonHeader->PointerToRawData;
            return Foa;
        }

        ++ImageSecitonHeader;
    }

    return NULL;
}