#include "StringHelper.h"
#include "dllmain.h"
int(*__lpfn_vsnwprintf)(wchar_t* Buffer, size_t Count, const wchar_t* const, va_list Args) = NULL;
int(*__lpfn_vsnprintf)(char* Buffer, size_t Count, const char* const, va_list Args) = NULL;
void InitializeString()
{


    *(FARPROC*)&__lpfn_vsnwprintf = GetProcAddress(__Ntdll, "_vsnwprintf");
    *(FARPROC*)&__lpfn_vsnprintf = GetProcAddress(__Ntdll, "_vsnprintf");
}


VOID
NTAPI
RtlInitUnicodeString(
    IN OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString)
{
    SIZE_T Size;
    CONST SIZE_T MaxSize = (MAXUSHORT & ~1) - sizeof(UNICODE_NULL); // an even number

    if (SourceString)
    {
        Size = wcslen(SourceString) * sizeof(WCHAR);
        __analysis_assume(Size <= MaxSize);

        if (Size > MaxSize)
            Size = MaxSize;
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = (USHORT)Size + sizeof(UNICODE_NULL);
    }
    else
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
}
WCHAR
NTAPI
RtlpUpcaseUnicodeChar(
    _In_ WCHAR Source)
{
    USHORT Offset = 0;

    if (Source < 'a')
        return Source;

    if (Source <= 'z')
        return (Source - ('a' - 'A'));

    return Source + (SHORT)Offset;
}
LONG
NTAPI
RtlCompareUnicodeString(
    IN PCUNICODE_STRING s1,
    IN PCUNICODE_STRING s2,
    IN BOOLEAN  CaseInsensitive)
{
    unsigned int len;
    LONG ret = 0;
    LPCWSTR p1, p2;

    len = min(s1->Length, s2->Length) / sizeof(WCHAR);
    p1 = s1->Buffer;
    p2 = s2->Buffer;

    if (CaseInsensitive)
    {
        while (!ret && len--) ret = RtlpUpcaseUnicodeChar(*p1++) - RtlpUpcaseUnicodeChar(*p2++);
    }
    else
    {
        while (!ret && len--) ret = *p1++ - *p2++;
    }

    if (!ret) ret = s1->Length - s2->Length;

    return ret;
}


int NlsStrCmp(const WCHAR* ParameterData1, const WCHAR* ParameterData2, ULONG Length)
{
    UNICODE_STRING v1, v2;

    v1.Length = v1.MaximumLength = v2.Length = v2.MaximumLength =
        (USHORT)(Length * sizeof(WCHAR));
    v1.Buffer = (WCHAR*)ParameterData1;
    v2.Buffer = (WCHAR*)ParameterData2;

    return RtlCompareUnicodeString(&v1, &v2, TRUE);
}






int __CRTDECL snwprintfEx(wchar_t* Buffer, size_t Count, const wchar_t* const Format, ...)
{
    int Result;
    va_list ArgList;

    extern int(*__lpfn_vsnwprintf)(wchar_t* Buffer, size_t Count, const wchar_t* const, va_list Args);

    va_start(ArgList, Format);
    Result = __lpfn_vsnwprintf(Buffer, Count, Format, ArgList);
    va_end(ArgList);

    if (Result == -1 && Buffer != NULL && Count != 0)
        Buffer[Count - 1] = 0; // ensure the resulting string is always null terminated

    return Result;
}

int __CRTDECL snprintfEx(char* Buffer, size_t Count, const char* const Format, ...)
{
    int Result;
    va_list ArgList;

    extern int(*__lpfn_vsnprintf)(char* Buffer, size_t Count, const char* const, va_list Args);

    va_start(ArgList, Format);
    Result = __lpfn_vsnprintf(Buffer, Count, Format, ArgList);
    va_end(ArgList);

    if (Result == -1 && Buffer != NULL && Count != 0)
        Buffer[Count - 1] = 0; // ensure the resulting string is always null terminated

    return Result;
}
