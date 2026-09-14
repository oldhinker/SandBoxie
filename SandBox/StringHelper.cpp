#include "StringHelper.h"


VOID NTAPI
RtlInitUnicodeString(
    IN OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString)
{
    SIZE_T DestSize;

    if (SourceString)
    {
        DestSize = wcslen(SourceString) * sizeof(WCHAR);
        DestinationString->Length = (USHORT)DestSize;
        DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
    }
    else
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
}
