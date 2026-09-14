#include "Common.h"
#include "InjectHelper.h"
#include "PeHelper.h"
#include "MemoryHelper.h"
void PrepareInjection(DATA_INFO* DataInfo, void* DetourCode)
{
    void* Ntdll;
    SYSCALLS_DATA* SyscallsData;
    INJECT_DATA* InjectData;
    EXTRA_DATA_INFO* ExtraDataInfo;
    ULONG LastError = 0;
   
    UCHAR* HookTarget = NULL;
    UCHAR* HookCode = NULL;;
    void* BaseAddress;
    SIZE_T RegionSize;
    ULONG OldProtect;
    //
    // now that syscalls were intercepted, we can use the top of the syscall
    // data area as a work area for injecting our dll, but we still need the
    // information from the extra area at the bottom of the data area
    //

    SyscallsData = (SYSCALLS_DATA*)DataInfo->SyscallsData;

    ExtraDataInfo = (EXTRA_DATA_INFO*)(DataInfo->SyscallsData + SyscallsData->ExtraDataInfoOffset);

    InjectData = (INJECT_DATA*)((UCHAR*)ExtraDataInfo + ExtraDataInfo->InjectDataOffset);

    InjectData->DataInfo = (ULONG64)DataInfo;

    //
    // in a 32-bit program on 64-bit Windows, we need to hook the
    // 32-bit ntdll (ntdll32) rather than the 64-bit ntdll, and we can
    // ask our driver for the base address of the 32-bit ntdll
    //

    Ntdll = (void*)DataInfo->Ntdll;

#ifdef _WIN64

    if (DataInfo->Flags.is_wow64) {

      
    }

#endif _WIN64

    //
    // find the addresses of the ntdll (or ntdll32) functions:
    // LdrLoadDll, LdrGetProcedureAddress, NtRaiseHardError,
    // and RtlFindActivationContextSectionString
    //

    InjectData->LdrLoadDll = (ULONG_PTR)FindDllExport(Ntdll,
        (UCHAR*)ExtraDataInfo + ExtraDataInfo->LdrLoadDllOffset, &LastError);
#ifdef _M_ARM64
#endif
    if (!InjectData->LdrLoadDll) {
    
        return;
    }

    InjectData->LdrGetProcAddr = (ULONG_PTR)FindDllExport(Ntdll,
        (UCHAR*)ExtraDataInfo + ExtraDataInfo->LdrGetProcAddrOffset, &LastError);
#ifdef _M_ARM64
  
#endif
    if (!InjectData->LdrGetProcAddr) {
      
        return;
    }

#ifdef _WIN64
    if (DataInfo->Flags.is_wow64) 
    {
    }
    else
#endif
    {
        //
        // for ARM64EC we need native functions, FindDllExport can manage FFS
        // however this does not work for syscalls, hence we use the native function directly
        //

        InjectData->NtProtectVirtualMemory = DataInfo->NtProtectVirtualMemory;   //字节指令
        InjectData->NtRaiseHardError = DataInfo->NtRaiseHardError;               //导出函数
        InjectData->NtDeviceIoControlFile = DataInfo->NtDeviceIoControlFile;     //字节指令
    }
    InjectData->DeviceHandle = DataInfo->DeviceHandle;
    

#ifdef _M_ARM64

    //
    // when hooking on arm64, go for LdrLoadDll 
    // instead of RtlFindActivationContextSectionString
    // for ARM64 both work, but for ARM64EC hooking RtlFindActCtx fails
    
    else
#endif
    {
        HookTarget = FindDllExport(Ntdll,
            (UCHAR*)ExtraDataInfo + ExtraDataInfo->RtlFindActCtxOffset, &LastError);    //RtlFindActivationContextSectionString
        if (!HookTarget) {
            return;
        }

        //FindActCtxSectionString 函数检索当前激活上下文中特定字符串的信息，并返回ACTCTX_SECTION_KEYED_DATA结构。


    }
    InjectData->RtlFindActCtx = (ULONG_PTR)HookTarget;


    InjectData->KernelDll.Length = (USHORT)ExtraDataInfo->KernelDllLength;
    InjectData->KernelDll.MaximumLength = InjectData->KernelDll.Length + sizeof(WCHAR);
    InjectData->KernelDll.Buffer32 =
        (ULONG)((ULONG_PTR)ExtraDataInfo + ExtraDataInfo->KernelDllOffset);
#ifdef _WIN64
    InjectData->KernelDll.Buffer64 =
        (ULONG64)((ULONG_PTR)ExtraDataInfo + ExtraDataInfo->KernelDllOffset);
#endif


#ifdef _M_ARM64
   
#endif
#ifdef _WIN64
        if (DataInfo->Flags.is_wow64)
        {
         
        }
        else
#endif
        {
            InjectData->NativeDll.Length = (SHORT)ExtraDataInfo->NativeDllLength;
            InjectData->NativeDll.MaximumLength = InjectData->NativeDll.Length + sizeof(WCHAR);
#ifdef _WIN64
            InjectData->NativeDll.Buffer64 =
                (ULONG64)((ULONG_PTR)ExtraDataInfo + ExtraDataInfo->NativeDllOffset);
#else
            InjectData->NativeDll.Buffer32 =
                (ULONG)((ULONG_PTR)ExtraDataInfo + ExtraDataInfo->NativeDllOffset);
#endif
        }

#ifdef _WIN64
        //64位下的64位
        if (!DataInfo->Flags.is_wow64)
        {

#ifdef _M_ARM64

#else
        HookCode = (UCHAR*)DetourCode;
        BaseAddress = (void*)(HookCode - 8);
        RegionSize = sizeof(ULONG_PTR);
        CALL(NtProtectVirtualMemory)(
            NtCurrentProcess(), &BaseAddress, &RegionSize,
            PAGE_EXECUTE_READWRITE, &OldProtect);
      



        *(ULONG_PTR*)(HookCode - 8) = (ULONG_PTR)InjectData;

        CALL(NtProtectVirtualMemory)(
            NtCurrentProcess(), &BaseAddress, &RegionSize,
            OldProtect, &OldProtect);

        BaseAddress = (void*)&HookTarget[0]; // RtlFindActCtx
        RegionSize = 12;
        CALL(NtProtectVirtualMemory)(
            NtCurrentProcess(), &BaseAddress, &RegionSize,
            PAGE_EXECUTE_READWRITE, &InjectData->RtlFindActCtx_Protect);
        memcpy(InjectData->RtlFindActCtx_Bytes, HookTarget, 12);

        HookTarget[0] = 0x48;
        HookTarget[1] = 0xb8;
        *(ULONG_PTR*)&HookTarget[2] = (ULONG_PTR)HookCode;
        HookTarget[10] = 0xff;
        HookTarget[11] = 0xe0;

#endif

        }
        else
        {
            //64位下的32位

#else
            //32位
#endif
           

        }


}


ULONG_PTR DetourProcedure(INJECT_DATA* InjectData)
{
    NTSTATUS Status;
    UNICODE_STRING* DllPath;
    HANDLE ModuleHandle;
    typedef VOID(*LPFN_1)(INJECT_DATA* InjectData);    //定义一个函数指针
    LPFN_1 Dll_Ordinal1 = NULL;
    void* BaseAddress;
    SIZE_T RegionSize;
    ULONG OldProtect;
    DATA_INFO* DataInfo;
#ifdef _WIN64
    DataInfo = InjectData->DataInfo;
#endif

    //
    // restore original function
    //

    BaseAddress = (void*)InjectData->RtlFindActCtx;   //源函数地址
#ifdef _WIN64
#ifdef _M_ARM64
   
#else
    RegionSize = 12;
    memcpy((void*)InjectData->RtlFindActCtx, InjectData->RtlFindActCtx_Bytes, 12);
#endif

    CALL(NtProtectVirtualMemory)(
        NtCurrentProcess(), &BaseAddress, &RegionSize,
        InjectData->RtlFindActCtx_Protect, &OldProtect);
#else
   
    //32位
#endif

    //
    // load kernel32.dll
    //

    DllPath = (UNICODE_STRING*)&InjectData->KernelDll;

    Status = ((LPFN_LDRLOADDLL)InjectData->LdrLoadDll)(NULL, 0, DllPath, &ModuleHandle);    //加载Kernel32.dll

    //
    // load sbiedll.dll
    //

    if (Status == 0) {

        DllPath = (UNICODE_STRING*)&InjectData->NativeDll;

        Status = ((LPFN_LDRLOADDLL)InjectData->LdrLoadDll)(NULL, 0, DllPath, &ModuleHandle);
    }

    //
    // get ordinal 1 from sbiedll
    //

    if (Status == 0) {

        Status = ((LPFN_LDRGETPROCEDUREADDRESS)InjectData->LdrGetProcAddr)(ModuleHandle, NULL, 1, (ULONG_PTR*)&Dll_Ordinal1);
#ifdef _M_ARM64

#endif
    }

    //
    // call ordinal 1 of sbiedll.dll
    //

    if (Status == 0) {

        Dll_Ordinal1(InjectData);
    }

    //
    // or report error if one occurred instead
    //

    else {


        Status = 0xC0000142; // = STATUS_DLL_INIT_FAILED
        ULONG_PTR Parameters[1] = { (ULONG_PTR)DllPath };
        ULONG LastError;
        ((LPFN_NTRAISEHARDERROR)InjectData->NtRaiseHardError)(
            Status | 0x10000000, // | FORCE_ERROR_MESSAGE_BOX
            1, 1, Parameters, 1, &LastError);
    }

    return Status;
}