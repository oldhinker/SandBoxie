#include "FileHelper.h"
#include "dllmain.h"

LPFN_NTOPENFILE __NtOpenFile = NULL;
LPFN_NTCLOSE __NtClose = NULL;
LPFN_NTDEVICEIOCONTROLFILE  __NtDeviceIoControlFile = NULL;
BOOLEAN InitializeFile(void)
{
    if (__Ntdll == NULL)
    {
        __Ntdll = GetModuleHandle(_T("ntdll.dll"));
    }
    __NtOpenFile = (LPFN_NTOPENFILE)GetProcAddress(__Ntdll, "NtOpenFile");


    __NtClose = (LPFN_NTCLOSE)GetProcAddress(__Ntdll, "NtClose");

 
    __NtDeviceIoControlFile = (LPFN_NTDEVICEIOCONTROLFILE)GetProcAddress(__Ntdll, "NtDeviceIoControlFile");



    if (!__NtOpenFile||!__NtClose ||!__NtDeviceIoControlFile)
        return false;
}