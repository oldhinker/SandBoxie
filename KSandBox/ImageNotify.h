#pragma once
#include "Common.h"

extern BOOLEAN __IsImageNotifyProcedure;

void ImageNotifyProcedure(
    const UNICODE_STRING* FullImageName,
    HANDLE ProcessIdentity, IMAGE_INFO* ImageInfo);