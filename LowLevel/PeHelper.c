#include "PeHelper.h"
UCHAR* FindDllExport(void* ModuleBase, const UCHAR* ServiceName, ULONG* Error)
{
    IMAGE_DOS_HEADER* ImageDosHeader;
    IMAGE_NT_HEADERS* ImageNtHeaders;
    UCHAR* ServiceAddress = NULL;

    //
    // find the DllMain entrypoint for the dll
    //

    ImageDosHeader = (void*)ModuleBase;
    if (ImageDosHeader->e_magic != 'MZ' && ImageDosHeader->e_magic != 'ZM') {
        if (Error) *Error = 0xa;
        return NULL;
    }
    ImageNtHeaders = (IMAGE_NT_HEADERS*)((UCHAR*)ImageDosHeader + ImageDosHeader->e_lfanew);
    if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {     // 'PE\0\0'
        if (Error) *Error = 0xb;
        return NULL;
    }

    if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {

        IMAGE_NT_HEADERS32* ImageNtHeaders32 = (IMAGE_NT_HEADERS32*)ImageNtHeaders;
        IMAGE_OPTIONAL_HEADER32* ImageOptionalHeader32 =
            &ImageNtHeaders32->OptionalHeader;

        if (ImageOptionalHeader32->NumberOfRvaAndSizes) {

            IMAGE_DATA_DIRECTORY* ImageDataDirectory = &ImageOptionalHeader32->DataDirectory[0];
            ServiceAddress = FindDllExportInternal(ModuleBase, ImageDataDirectory, ServiceName, Error);
        }
    }

#ifdef _WIN64

    else if (ImageNtHeaders->OptionalHeader.Magic ==
        IMAGE_NT_OPTIONAL_HDR64_MAGIC) {

        IMAGE_NT_HEADERS64* ImageNtHeaders64 = (IMAGE_NT_HEADERS64*)ImageNtHeaders;
        IMAGE_OPTIONAL_HEADER64* ImageOptionalHeader64 =
            &ImageNtHeaders64->OptionalHeader;

        if (ImageOptionalHeader64->NumberOfRvaAndSizes) {

            IMAGE_DATA_DIRECTORY* ImageDataDirectory = &ImageOptionalHeader64->DataDirectory[0];
            ServiceAddress = FindDllExportInternal(ModuleBase, ImageDataDirectory, ServiceName, Error);
        }
    }

#endif _WIN64

    return ServiceAddress;
}
UCHAR* FindDllExportInternal(
    void* ModuleBase, IMAGE_DATA_DIRECTORY* ImageDataDirectory, const UCHAR* ServiceName, ULONG* Error)
{
    void* ServiceAddress = NULL;
    ULONG i, j, n;

    if (ImageDataDirectory->VirtualAddress && ImageDataDirectory->Size) 
    {

        IMAGE_EXPORT_DIRECTORY* ImageExportDirectory = (IMAGE_EXPORT_DIRECTORY*)
            ((UCHAR*)ModuleBase + ImageDataDirectory->VirtualAddress);

        ULONG* AddressOfNames = (ULONG*)
            ((UCHAR*)ModuleBase + ImageExportDirectory->AddressOfNames);

        for (n = 0; ServiceName[n]; ++n)     //计算函数名称的长度
            ;

        for (i = 0; i < ImageExportDirectory->NumberOfNames; ++i) 
        {

            UCHAR* v1 = (UCHAR*)ModuleBase + AddressOfNames[i];
            for (j = 0; j < n; ++j) {
                if (v1[j] != ServiceName[j])    //查找函数名称
                    break;
            }
            if (j == n) {

                USHORT* AddressOfNameOrdinals = (USHORT*)
                    ((UCHAR*)ModuleBase + ImageExportDirectory->AddressOfNameOrdinals);
                if (AddressOfNameOrdinals[i] < ImageExportDirectory->NumberOfFunctions) {

                    ULONG* AddressOfFunctions = (ULONG*)
                        ((UCHAR*)ModuleBase + ImageExportDirectory->AddressOfFunctions);

                    ServiceAddress = (UCHAR*)ModuleBase + AddressOfFunctions[AddressOfNameOrdinals[i]];
                    break;
                }
            }
        }

        if (ServiceAddress && (ULONG_PTR)ServiceAddress >= (ULONG_PTR)ImageExportDirectory
            && (ULONG_PTR)ServiceAddress < (ULONG_PTR)ImageExportDirectory + ImageDataDirectory->Size) {

            //
            // if the export points inside the export table, then it is a
            // forwarder entry.  we don't handle these, because none of the
            // exports we need is a forwarder entry.  if this changes, we
            // might have to scan LDR tables to find the target dll
            //
            //转发器

            if (Error) *Error = 0xc;
            ServiceAddress = NULL;
        }
    }

    return ServiceAddress;
}