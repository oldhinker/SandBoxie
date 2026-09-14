#pragma once
#include "Common.h"


#pragma pack(1)

typedef struct _TRAMPOLINE_ {

    ULONG EyeCatcher;                   // (0,4) signature

    ULONG DataLength;                         // (4,4) tramp size (multiple of 16)

    void* TargetAddress;                       // (8,4/8) branch target in source

    __declspec(align(16))
        UCHAR CodeData[64];                 // (16) source code + extra jmp

    ULONG ByteCount;						// original length of relocated code

}TRAMPOLINE;
void* BuildHookTrampoline(
    void* ServiceAddress, void* Trampoline, BOOLEAN Is64, BOOLEAN IsProbe);


BOOLEAN GetTrampolineLength(
    void* ServiceAddress, ULONG* ByteCount, BOOLEAN Is64, BOOLEAN IsProbe);

BOOLEAN GetTrampolienCode(
    _TRAMPOLINE_* Trampoline, void* ServiceAddress,
    ULONG ByteCount, BOOLEAN Is64, BOOLEAN IsProbe);