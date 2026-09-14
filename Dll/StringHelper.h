#pragma once
#include "Common.h"


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR* Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;
#define UNICODE_NULL ((WCHAR)0)

typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    UCHAR* Buffer;
} ANSI_STRING;
typedef ANSI_STRING* PANSI_STRING;
typedef const ANSI_STRING* PCANSI_STRING;

typedef struct _UNICODE_STRING64 {
    USHORT Length;
    USHORT MaximumLength;
    __declspec(align(8)) unsigned __int64 Buffer;
} UNICODE_STRING64;



typedef struct _UNIVERSAL_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    ULONG   Buffer32;
    ULONG64 Buffer64;
} UNIVERSAL_STRING;

#define MAXUSHORT USHRT_MAX


void InitializeString();

int NlsStrCmp(const WCHAR* ParameterData1, const WCHAR* ParameterData2, ULONG Length);


VOID
NTAPI
RtlInitUnicodeString(
    IN OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString);

LONG
NTAPI
RtlCompareUnicodeString(
    IN PCUNICODE_STRING s1,
    IN PCUNICODE_STRING s2,
    IN BOOLEAN  CaseInsensitive);
WCHAR
NTAPI
RtlpUpcaseUnicodeChar(
    _In_ WCHAR Source);


int __CRTDECL snprintfEx(char* Buffer, size_t Count, const char* const Format, ...);
int __CRTDECL snwprintfEx(wchar_t* Buffer, size_t Count, const wchar_t* const Format, ...);