#pragma once
#include "Common.h"

UCHAR* FindDllExport(void* ModuleBase, const UCHAR* ServiceName, ULONG* Error);

UCHAR* FindDllExportInternal(
    void* ModuleBase, IMAGE_DATA_DIRECTORY* ImageDataDirectory, const UCHAR* ServiceName, ULONG* Error);