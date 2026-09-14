#include "Syscall.h"


ULONG GetServiceIndex(UCHAR* ServiceAddress)
{
    ULONG ServiceIndex = -1;

    if (*ServiceAddress == 0xB8)                      // mov eax, syscall number
        ServiceIndex = *(ULONG*)(ServiceAddress + 1);

    if (ServiceIndex == -1)
    {

    }
    return ServiceIndex;
}