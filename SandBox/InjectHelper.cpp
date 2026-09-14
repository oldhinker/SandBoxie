#include "InjectHelper.h"
#include "_tWinMain.h"
#include "DriverAssist.h"
#include "ApiHelper.h"
#include "MemoryHelper.h"
#include "FileHelper.h"
#include "IoRequest.h"
void* __TestAddress = NULL;
ULONG __TestLength = 0;
//adding two offsets variables to replace the "head" and "tail" dependency
ULONG __StartOffset = 0;
ULONG __DataInfoOffset = 0;

#ifdef _WIN64
void* __TestAddress86 = NULL;
ULONG __TestLength86 = 0;
ULONG __DetourCodeOffset86 = 0;
#endif


/*
0:000> u 0x0000000077bcc340
ntdll!LdrInitializeThunk:
00000000`77bcc340 e9cb3c4688      jmp     00000000`00030010
00000000`77bcc345 20488b          and     byte ptr [rax-75h],cl
00000000`77bcc348 d9e8            fld1
00000000`77bcc34a 2200            and     al,byte ptr [rax]
00000000`77bcc34c 0000            add     byte ptr [rax],al
00000000`77bcc34e b201            mov     dl,1
00000000`77bcc350 488bcb          mov     rcx,rbx
00000000`77bcc353 e888530200      call    ntdll!NtContinue (00000000`77bf16e0)


*/


ULONG_PTR __LdrInitializeThunk = 0;

ULONG InjecitonPrepare()
{


#ifdef _WIN64
	ULONG Error = InjecitonPrepareInternal(FALSE, &__TestAddress, &__TestLength, &__StartOffset,
		&__DataInfoOffset, NULL);

    /*
	if (!Error)
        Error = InjecitonHelperInternal(TRUE, &__TestAddress86, &__TestLength86,
			NULL, NULL, &__DetourCodeOffset86);
            */
#else
	ULONG Error = InjecitonHelperInternal(TRUE, &__TestAddress,
		&__TestLength, &__StartOffset, &__DataInfoOffset, NULL);
#endif
	if (Error)
		return Error;
 
    //
    // record information about ntdll and the virtual memory system
    //

    Error = 0x33;

    __LdrInitializeThunk = (ULONG_PTR)GetProcAddress(__Ntdll, "LdrInitializeThunk");

    if (!__LdrInitializeThunk)
        return Error;

#ifdef _M_ARM64

    //
    // for x64 on arm64 we need the EC version of LdrInitializeThunk as well as VirtualAlloc2, 
    // if those are missing we will only fail SbieDll_InjectLow for x64 processes on arm64
    //

    WCHAR path[MAX_PATH];
    if (!GetSystemDirectory(path, MAX_PATH))
        wcscpy(path, L"C:\\Windows\\System32");
    wcscat(path, L"\\ntdll.dll");

    m_LdrInitializeThunkEC = (ULONG_PTR)Dll_Ntdll + FindDllExportFromFile(path, "#LdrInitializeThunk");

    __sys_VirtualAlloc2 = (P_VirtualAlloc2)GetProcAddress(Dll_KernelBase, "VirtualAlloc2");

#elif _WIN64

    /*
    if (__Windows >= 10) {
        unsigned char* v1;
        v1 = (unsigned char*)__LdrInitializeThunk;
        if (*(ULONG*)&v1[0] == 0x24048b48 && v1[0xa] == 0x48) {
            __LdrInitializeThunk += 0xa;
        }
    }*/
#endif


	
	return 0;
}

ULONG InjecitonPrepareInternal(BOOLEAN IsWow64, void** TextAddress, ULONG* TextLength,
    ULONG* StartOffset, ULONG* DataInfoOffset, ULONG* DetourCodeOffset)
{
    //
    // lock the SbieLow resource (embedded within the SbieSvc executable,
    // see lowlevel.rc) and find the offset to executable code, and length
    //

    IMAGE_DOS_HEADER* ImageDosHeader = 0;
    IMAGE_NT_HEADERS* ImageNtHeaders = 0;
    IMAGE_SECTION_HEADER* ImageSectionHeader = 0;
    IMAGE_DATA_DIRECTORY* ImageDataDirectory = 0;
    ULONG_PTR ImageBase = 0;
    
    MY_TARGETS* MyTargets = 0;

    ULONG Error = 0x11;

    /*
  
    */

    /*
    HRSRC ResourceHandle = FindResource(Dll_Instance, IsWow64 ? L"LOWLEVEL32" : L"LOWLEVEL64", RT_RCDATA);
    if (!ResourceHandle)
        return Error;

    ULONG v7 = SizeofResource(Dll_Instance, ResourceHandle);
    if (!v7)
        return Error;

    HGLOBAL v5 = LoadResource(Dll_Instance, v7);
    if (!hglob)
        return Error;

    UCHAR* VirtualAddress = (UCHAR*)LockResource(v5);
    if (!VirtualAddress)
        return Error;
    */
    TCHAR v1[MAX_PATH] = { 0 };

    GetCurrentDirectory(MAX_PATH, v1);
#ifdef _WIN64
    _tcscat_s(v1, _T("\\x64\\Debug\\LowLevel.dll"));
#else
    _tcscat_s(v1, _T("\\Debug\\LowLevel.dll"));
#endif
    DWORD FileSizeLow = 0;
    DWORD FileSizeHigh = 0;
    UCHAR* BufferData = NULL;
    DWORD NumberOfBytesRead = 0;
    BOOL  IsOk = FALSE;
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
    FileHandle = CreateFile(v1,
        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);  //打开文件获得文件句柄

    if (FileHandle != INVALID_HANDLE_VALUE)
    {
        FileSizeLow = GetFileSize(FileHandle, &FileSizeHigh);
        BufferData = (UCHAR*)malloc(FileSizeLow + 0x1000);

        IsOk = ReadFile(FileHandle, BufferData, FileSizeLow, &NumberOfBytesRead, 0);
    }


    Error = 0x22;
    ImageDosHeader = (IMAGE_DOS_HEADER*)BufferData;

    if (ImageDosHeader->e_magic == 'MZ' || ImageDosHeader->e_magic == 'ZM') {
        ImageNtHeaders = (IMAGE_NT_HEADERS*)((UCHAR*)ImageDosHeader + ImageDosHeader->e_lfanew);

        if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)   // 'PE\0\0'
            return Error;
        if (ImageNtHeaders->OptionalHeader.Magic != (IsWow64 ? IMAGE_NT_OPTIONAL_HDR32_MAGIC: IMAGE_NT_OPTIONAL_HDR64_MAGIC))
            return Error;

        if (IsWow64) {
            IMAGE_NT_HEADERS32* ImageNtHeaders32 = (IMAGE_NT_HEADERS32*)ImageNtHeaders;
            IMAGE_OPTIONAL_HEADER32* ImageOptionalHeader32 = &ImageNtHeaders32->OptionalHeader;
            ImageDataDirectory = &ImageOptionalHeader32->DataDirectory[0];
            ImageBase = ImageOptionalHeader32->ImageBase;
        }
        else {
            IMAGE_NT_HEADERS64* ImageNtHeaders64 = (IMAGE_NT_HEADERS64*)ImageNtHeaders;
            IMAGE_OPTIONAL_HEADER64* ImageOptionalHeader64 = &ImageNtHeaders64->OptionalHeader;
            ImageDataDirectory = &ImageOptionalHeader64->DataDirectory[0];
            ImageBase = (ULONG_PTR)ImageOptionalHeader64->ImageBase;
        }
    }

    ULONG v100 = 1;
#ifdef _M_ARM64
    if (!IsWow64)
        v100 = 3; // ARM64 only
    else
#endif
        if (ImageBase != 0) // x64 or x86
            return Error;

    ImageSectionHeader = IMAGE_FIRST_SECTION(ImageNtHeaders);
    if (ImageNtHeaders->FileHeader.NumberOfSections < 2) return Error;
    if (strncmp((char*)ImageSectionHeader[0].Name, INJECTION_SECTION, strlen(INJECTION_SECTION)) ||
        strncmp((char*)ImageSectionHeader[v100].Name, SYMBOL_SECTION, strlen(SYMBOL_SECTION))) {
        return Error;
    }





    MyTargets = (MY_TARGETS*)&BufferData[ImageSectionHeader[v100].PointerToRawData];   //文件粒度
    if (StartOffset) *StartOffset = (ULONG)(MyTargets->Start - ImageBase - ImageSectionHeader[0].VirtualAddress);
    if (DataInfoOffset) *DataInfoOffset = (ULONG)(MyTargets->DataInfo - ImageBase - ImageSectionHeader[0].VirtualAddress);
    if (DetourCodeOffset) *DetourCodeOffset = (ULONG)(MyTargets->DetourCode - ImageBase - ImageSectionHeader[0].VirtualAddress);

    *TextAddress = BufferData + ImageSectionHeader[0].PointerToRawData; //Old version: head;
    *TextLength = ImageSectionHeader[0].SizeOfRawData; //Old version: (ULONG)(ULONG_PTR)(tail - head);

    /*
    * txt
    0x00000000003592C0  48 8d 41 30 c3 cc cc cc cc cc cc cc cc cc cc cc 48 83 ec 28 48 89 4c 24 20 48 89 54 24 28 4c 89 44 24 30 4c 89 4c 24 38 e8 00 00 00 00 59 48 8b d9 48 81 c1 40 00 00 00 48 8b d3 48 81  H?A0????????????H??(H?L$ H?T$(L?D$0L?L$8?....YH??H??@...H??H?
    0x00000000003592FD  c2 3e 00 00 00 4c 8b c3 49 81 c0 3e 00 00 00 e8 af ff ff ff 48 8b 4c 24 20 48 8b 54 24 28 4c 8b 44 24 30 4c 8b 4c 24 38 48 83 c4 28 ff e0 90 90 00 00 00 00 00 00 00 00 00 00 00 00 00  ?>...L??I??>...??...H?L$ H?T$(L?D$0L?L$8H??(.???.............
    */
    // 48 8d 41 30 c3 cc cc cc cc cc cc cc cc cc cc cc    EntryPointC
    //




    /*
    if (BufferData!=NULL)
    {
        delete BufferData;
        BufferData;

    }
    */

    return 0;
}



void CDriverAssist::InjectProcessReply(void* MessageData)
{


    PPROCESS_MESSAGE v1 = (PPROCESS_MESSAGE)MessageData;

    NTSTATUS Status = 0;
    ULONG LastError = 0;
    HANDLE ProcessHandle = NULL;


    UCHAR SandboxieLogonSid[SECURITY_MAX_SID_SIZE] = { 0 };
    WCHAR* file_root_path = NULL;
    WCHAR* reg_root_path = NULL;



    if (!m_IsDriverReady) {

        LastError = 0xFF;
        goto Exit;
    }

    //
    // open new process and verify process creation time
    //

    ProcessHandle = OpenProcess(MessageData);
    if (!ProcessHandle) {

        LastError = 0x11;
        goto Exit;
    }


   
    LastError = InjectProcess(ProcessHandle, 0, TRUE);
    if (LastError != 0)
        goto Exit;




    if (0)
    {

    }
    else
    {
        Status = IoctlRequest(INJECT_COMPLETE, 1, (ULONG_PTR)v1->ProcessIdentity);
    }
       

    if (Status == 0)
        LastError = 0;
    else
        LastError = 0x99;
  
Exit:;

    if (LastError) {

        ULONG v1 = GetLastError();
     
    }

    if (ProcessHandle) {

        if (LastError) 
        {

            int v1 = 0;
            //SbieApi_Call(API_INJECT_COMPLETE, 3, (ULONG_PTR)msg->process_id, NULL, errlvl);
            //TerminateProcess(hProcess, 1);
        }

        CloseHandle(ProcessHandle);
    }
}


HANDLE CDriverAssist::OpenProcess(void* MessageData)
{
    PPROCESS_MESSAGE v1 = (PPROCESS_MESSAGE)MessageData;

    ///
    // open target process with the access rights we need
    //

    const ULONG DesiredAccess =
        PROCESS_DUP_HANDLE | PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME
        | PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;

    HANDLE ProcessHandle = ::OpenProcess(DesiredAccess, FALSE, v1->ProcessIdentity);

    if (ProcessHandle) {

        FILETIME FileTime1, FileTime2, FileTime3, FileTime4;
        BOOL IsOk = GetProcessTimes(ProcessHandle, &FileTime1, &FileTime2, &FileTime3, &FileTime4);
        if (IsOk && *(ULONG64*)&FileTime1.dwLowDateTime == v1->CreateTime)
        {

            return ProcessHandle;
        }

        CloseHandle(ProcessHandle);
    }

    return NULL;
}

ULONG InjectProcess(HANDLE ProcessHandle, ULONG Flags, BOOLEAN IsDuplicateHandle)
{
	ULONG LastError = 0;
    void* v5 = NULL;
    SIZE_T v7; 
    void* v10 = NULL;
    BOOLEAN IsJumpTable = FALSE;
    ULONG_PTR Trampoline = 0;
    DATA_INFO DataInfo;   //目标进程空间中的内存
	memset(&DataInfo, 0, sizeof(DataInfo));

    DataInfo.Flags.init_flags = Flags;

#ifdef _M_ARM64

#endif

	//
	// verify all aspects of initialization were successful
	//



	if ((!__TestAddress) || (!__SyscallsData)
#ifdef _M_ARM64
#endif
		) {

		SetLastError(ERROR_NOT_READY);
        LastError = 0xFF;
		goto Exit;
	}

    DataInfo.Ntdll = (ULONG64)(ULONG_PTR)__Ntdll;


    static const WCHAR* _Ntdll= L"\\system32\\ntdll.dll";    // 19 chars



    DataInfo.NtDeviceIoControlFile = (ULONG64)GetProcAddress((HMODULE)DataInfo.Ntdll, "NtDeviceIoControlFile");
    DataInfo.NtProtectVirtualMemory = (ULONG64)GetProcAddress((HMODULE)DataInfo.Ntdll, "NtProtectVirtualMemory");
    DataInfo.NtRaiseHardError = (ULONG64)GetProcAddress((HMODULE)DataInfo.Ntdll, "NtRaiseHardError");

    //
    // on 64-bit Windows 8, there might be a difference of more than
    // 2GB bytes between ntdll and the injected SbieLow, which requires
    // use of longer jump sequences than the 5-byte 0xE9 relative jump
    //
    if (__Windows >= 10) {
        DataInfo.Flags.is_win10 = 1;
    }


  
#ifdef _WIN64 
  
    if (IsJumpTable)
        v7 = __TestLength + sizeof(JUMP_TABLE) + 0x400;
    else
#endif
        v7 = __TestLength;

    v5 = CopyShellCode(ProcessHandle, v7, __TestLength, __TestAddress
#ifdef _M_ARM64
#endif
    );

    //将ShellCode写入到目标进程空间中
    if (v5) {

        void* LdrInitializeThunk = (void*)__LdrInitializeThunk;

        /*
        0000000077BCC340 FF F3                push        rbx  
        0000000077BCC342 48 83 EC 20          sub         rsp,20h  
        0000000077BCC346 48 8B D9             mov         rbx,rcx  
        0000000077BCC349 E8 22 00 00 00       call        0000000077BCC370  
        0000000077BCC34E B2 01                mov         dl,1  
        0000000077BCC350 48 8B CB             mov         rcx,rbx  
        0000000077BCC353 E8 88 53 02 00       call        0000000077BF16E0  
        0000000077BCC358 8B C8                mov         ecx,eax  
        0000000077BCC35A E8 71 14 0A 00       call        0000000077C6D7D0  
        0000000077BCC35F CC                   int         3  
        
        */




#ifdef _M_ARM64

#endif

        //
        // copy code at LdrInitializeThunk from new process
        //

        SIZE_T Length1 = sizeof(DataInfo.LdrInitializeThunk_tramp);
        SIZE_T Length2 = 0;
        /*
        sprintf(buffer,"CopyCode: copy ldr size %d\n",code_len);
        OutputDebugStringA(buffer);
        */


        //获取远程函数地址 ??????????????????????????????????????????????
        BOOL IsOk = ReadProcessMemory(
            ProcessHandle, LdrInitializeThunk, DataInfo.LdrInitializeThunk_tramp,
            Length1, &Length2);


        /*
    
        000000000287EFA0 FF F3                push        rbx
        000000000287EFA2 48 83 EC 20          sub         rsp,20h
        000000000287EFA6 48 8B D9             mov         rbx,rcx
        000000000287EFA9 E8 22 00 00 00       call        000000000287EFD0
        000000000287EFAE B2 01                mov         dl,1
        000000000287EFB0 48 8B CB             mov         rcx,rbx
        000000000287EFB3 E8 88 53 02 00       call        00000000028A4340
        000000000287EFB8 8B C8                mov         ecx,eax
        000000000287EFBA E8 71 14 0A 00       call        0000000002920430
        000000000287EFBF CC                   int         3


        */

        if (!IsOk || Length1 != Length2) {

            //释放目标进程中的内存 ??????????????????????????????????????????????????????
            v5 = NULL;
        }
    }
    if (!v5) {
        LastError = 0x33;
        goto Exit;
    }

#ifdef _WIN64 
    if (DataInfo.Flags.is_wow64)
    {

        //
        // when this is a 32 bit process running under WoW64, we need to inject also some 32 bit code
        //

        //void* remote_addr32 = SbieDll_InjectLow_CopyCode(hProcess, m_sbielow32_len, m_sbielow32_len, m_sbielow32_ptr
#ifdef _M_ARM64
#endif
        //);

        /*
        if (v5) {

      
        }

        if (!SyscllsData.ptr_32bit_detour)
        {
            LastError = 0x88;
            goto Exit;
        }*/
    }
#endif

#ifndef _M_ARM64
#ifdef _WIN64
    DataInfo.Flags.long_diff = 1;


    if (Has32BitJumpHorizon((void*)__LdrInitializeThunk, v5))
    {
        DataInfo.Flags.long_diff = 0;
    }
#else
    SyscllsData.Flags.long_diff = 0;
#endif
#endif
    if (IsDuplicateHandle)
    {
        //
        // duplicate the SbieDrv API file device handle into target process
        //

        DataInfo.DeviceHandle = (ULONG64)(ULONG_PTR)
            CopyDeviceHandle(ProcessHandle);
        if (!DataInfo.DeviceHandle) {

            LastError = 0x22;
            goto Exit;
        }

        DataInfo.IoControlCode = IO_CTL_CODE_1;
        DataInfo.InvokeSyscalls = INVOKE_SYSCALLS;
    }
    //拷贝了4个函数的原始指令
    memcpy(DataInfo.NtDelayExecution_code, &__SyscallsData[2], (NATIVE_FUNCTION_SIZE* NATIVE_FUNCTION_COUNT));

    /*
    0000000000389660 C0 0E 00             ror         byte ptr [rsi],0  
    0000000000389663 00 E0                add         al,ah  
    0000000000389665 0C 00                or          al,0  
    0000000000389667 00 4C 8B D1          add         byte ptr [rbx+rcx*4-2Fh],cl  
    000000000038966B B8 31 00 00 00       mov         eax,31h  
    0000000000389670 0F 05                syscall 


    PROCESS fffffa806332d060
    SessionId: 1  Cid: 0de0    Peb: 7fffffd8000  ParentCid: 0a10
    DirBase: 210a49000  ObjectTable: fffff8a002f73380  HandleCount:  24.
    Image: SandBox.exe

    kd> .process /i fffffa806332d060
    You need to continue execution (press 'g' <enter>) for the context
    to be switched. When the debugger breaks in again, you will be in
    the new process context.
    kd> g
    Break instruction exception - code 80000003 (first chance)
    nt!RtlpBreakWithStatusInstruction:
    fffff800`03e709f0 cc              int     3
    kd> u 0000000000389660
    00000000`00389660 c00e00          ror     byte ptr [rsi],0
    00000000`00389663 00e0            add     al,ah
    00000000`00389665 0c00            or      al,0
    00000000`00389667 004c8bd1        add     byte ptr [rbx+rcx*4-2Fh],cl
    00000000`0038966b b831000000      mov     eax,31h
    00000000`00389670 0f05            syscall

    
    */




#ifdef _WIN64
    if (IsJumpTable)
    {
        //    SyscllsData.x64BitJumpTable = (SBIELOW_J_TABLE*)((ULONG_PTR)remote_addr + m_sbielow_len + 0x400); //(0x400 - (m_sbielow_len & 0x3ff))+ m_sbielow_len;
    }  
#endif
    //ULONG_PTR v1000 = FIELD_OFFSET(_SYSCALLS_DATA_, LdrInitializeThunk_tramp);
    Trampoline = (ULONG_PTR)v5 + __DataInfoOffset + FIELD_OFFSET(DATA_INFO, LdrInitializeThunk_tramp);

    if (!BuildTrampoline(DataInfo.Flags.long_diff == 1,
        DataInfo.LdrInitializeThunk_tramp, Trampoline
#ifdef _M_ARM64
        , (BOOLEAN)lowdata.flags.is_arm64ec
#endif
    )) {
        SetLastError(ERROR_UNKNOWN_PRODUCT);

        LastError = 0x44;
        goto Exit;
    }
    /*
    000000000293F550 FF F3                push        rbx  
    000000000293F552 48 83 EC 20          sub         rsp,20h  
    000000000293F556 48 8B D9             mov         rbx,rcx  
    000000000293F559 E8 22 00 00 00       call        000000000293F580  
    000000000293F55E B2 01                mov         dl,1  
    000000000293F560 48 8B CB             mov         rcx,rbx  
    000000000293F563 E8 88 53 02 00       call        00000000029648F0  
    000000000293F568 8B C8                mov         ecx,eax  
    000000000293F56A E8 71 14 0A 00       call        00000000029E09E0  
    000000000293F56F CC                   int         3  
    


    000000000293F550 FF F3                push        rbx
    000000000293F552 48 83 EC 20          sub         rsp,20h
    000000000293F556 E9 F4 C2 A2 77       jmp         000000007A36B84F
    000000000293F55B 00 00                add         byte ptr [rax],al
    000000000293F55D 00 B2 01 48 8B CB    add         byte ptr [rdx-3474B7FFh],dh
    000000000293F563 E8 88 53 02 00       call        00000000029648F0
    000000000293F568 8B C8                mov         ecx,eax
    000000000293F56A E8 71 14 0A 00       call        00000000029E09E0
    000000000293F56F CC                   int         3
    
    */
    v10 = CopySyscalls(ProcessHandle, (BOOLEAN)DataInfo.Flags.is_wow64
#ifdef _M_ARM64
        , (BOOLEAN)lowdata.flags.is_arm64ec
#endif
    );
    if (!v10) {

        LastError = 0x55;
        goto Exit;
    }

    DataInfo.SyscallsData = (ULONG64)(ULONG_PTR)v10;


    if (!CopyData(ProcessHandle, v5, &DataInfo)) {

        LastError = 0x66;
        goto Exit;
    }

    if (!WriteJump(ProcessHandle, (UCHAR*)v5 + __StartOffset, DataInfo.Flags.long_diff == 1
#ifdef _M_ARM64
        , (BOOLEAN)lowdata.flags.is_arm64ec
#endif
    )) {
        LastError = 0x77;
        goto Exit;
    }

    /*
    * __LdrInitializeThunk
    kd> u 0x0000000077bcc340
    00000000`77bcc340 e9cb3c5488      jmp     00000000`00110010
    00000000`77bcc345 20488b          and     byte ptr [rax-75h],cl

    
    
    
    
    
    
    */




Exit:
	return LastError;
}

void* CopyShellCode(HANDLE ProcessHandle, SIZE_T ViewSize, SIZE_T TestLength, const void* TestAddress
#ifdef _M_ARM64
#endif
) {

    void* v5 = AllocateRemoteMemory(ProcessHandle, ViewSize, TRUE        //目标进程中申请内存
#ifdef _M_ARM64
#endif
    );

    if (v5) {

        //
        // copy SbieLow into the allocated region in the new process
        //

        SIZE_T Length1 = TestLength;
        SIZE_T Length2 = 0;
        BOOL IsOk = WriteProcessMemory(
            ProcessHandle, v5, TestAddress,
            Length1, &Length2);

        if (IsOk && Length1 == Length2) {

            return v5;
        }
        /*
        kd> .process /i fffffa8062b1eb30
        You need to continue execution (press 'g' <enter>) for the context
        to be switched. When the debugger breaks in again, you will be in
        the new process context.
        kd> g
        Break instruction exception - code 80000003 (first chance)
        nt!RtlpBreakWithStatusInstruction:
        fffff800`03e709f0 cc              int     3
        kd> db 0x0000000000130000
        00000000`00130000  00 86 9b ef fe 07 00 00-7e 00 00 00 02 00 00 00  ........~.......
        00000000`00130010  78 00 00 00 00 00 00 00-7c 00 00 00 fd fd fd fd  x.......|.......
        00000000`00130020  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
        00000000`00130030  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
        00000000`00130040  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
        00000000`00130050  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
        00000000`00130060  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
        00000000`00130070  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ..............
        
        */
        /*
        0x00000000003392C0  00 86 9b ef fe 07 00 00 7e 00 00 00 02 00 00 00 78 00 00 00 00 00 00 00 7c 00 00  .????...~.......x.......|..
        0x00000000003392DB  00 fd fd fd fd 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  .????......................
        0x00000000003392F6  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ...........................
        0x0000000000339311  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ...........................
        0x000000000033932C  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ...........................
        0x0000000000339347  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 fd fd fd fd dd dd dd dd dd dd  .................??????????
        0x0000000000339362  dd dd dd dd dd dd b0 96 ff 39 6f d0 00 14 20 df 33 00 00 00 00 00 10 eb 33 00 00  ????????.9o?.. ?3......?3..
        0x000000000033937D  00 00 00 00 86 9b ef fe 07 00 00 7e 00 00 00 02 00 00 00 78 00 00 00 00 00 00 00  
        
        */




    }

    return NULL;
}
void* AllocateRemoteMemory(HANDLE ProcessHandle, SIZE_T ViewSize, BOOLEAN IsExecutable
#ifdef _M_ARM64
#endif
) {
    SIZE_T v7 = ViewSize;
    void* v5 = NULL;

#ifdef _M_ARM64
 
#endif

    //
    // allocate virtual memory somewhere in the process.  to force an
    // address in the low 24-bits of the address space, we have to use
    // NtAllocateVirtalMemory and specify ZeroBits = 8 (32 - 8 = 24)
    //

    //for (int i = 8; !remote_addr && i > 2; i--) {
    for (int i = 8; !v5 && i >= 0; i--) {
        NTSTATUS Status = __NtAllocateVirtualMemory(ProcessHandle,
            &v5, i, &v7, MEM_COMMIT | MEM_RESERVE, IsExecutable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
        if (!NT_SUCCESS(Status)) {
          
            v5 = NULL;
            v7 = ViewSize;
        }
    }

    return v5;
}
HANDLE CopyDeviceHandle(HANDLE ProcessHandle)
{
    NTSTATUS Status;
    HANDLE DeviceHandle, v5;
    UNICODE_STRING v1;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;

    //
    // open the Sandboxie driver API file handle
    //

    RtlInitUnicodeString(&v1, DEVICE_NAME);
    InitializeObjectAttributes(
        &ObjectAttributes, &v1, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = __NtOpenFile(
        &DeviceHandle, FILE_GENERIC_READ, &ObjectAttributes, &IoStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);

    if (NT_SUCCESS(Status)) {

        //
        // duplicate opened handle into new process
        //

        BOOL IsOk = DuplicateHandle(NtCurrentProcess(), DeviceHandle,
            ProcessHandle, &v5, 0, FALSE,
            DUPLICATE_SAME_ACCESS);

        CloseHandle(DeviceHandle);

        if (IsOk) {

            return v5;
        }
    }

    return NULL;
}
BOOLEAN BuildTrampoline(
    BOOLEAN Diff, UCHAR* CodeData, ULONG_PTR VirtualAddress
#ifdef _M_ARM64
    , BOOLEAN use_arm64ec
#endif
) {

#ifdef _M_ARM64
#else

#define IS_1BYTE(a)     (                 CodeData[Offset + 0] == (a))
#define IS_2BYTE(a,b)   (IS_1BYTE(a)   && CodeData[Offset + 1] == (b))
#define IS_3BYTE(a,b,c) (IS_2BYTE(a,b) && CodeData[Offset + 2] == (c))

    //
    // skip past several bytes in the code copied from the top of the
    // LdrInitializeThunk function, where we will inject a jmp sequence.
    //
    // a simple E9 relative JMP five byte instruction in most cases,
    // a slightly longer seven byte version in case there is a long
    // distance between ntdll and SbieLow, i.e. on 64-bit Windows 8
    //

#ifdef _WIN64
    ULONG CodeLength = (Diff ? 7 : ((__Windows >= 10) ? 6 : 5));
#else
    ULONG CodeLength = 5;
#endif


    /*
      0000000077BCC340 FF F3                push        rbx
      0000000077BCC342 48 83 EC 20          sub         rsp,20h
      0000000077BCC346 48 8B D9             mov         rbx,rcx
      0000000077BCC349 E8 22 00 00 00       call        0000000077BCC370
      0000000077BCC34E B2 01                mov         dl,1
      0000000077BCC350 48 8B CB             mov         rcx,rbx
      0000000077BCC353 E8 88 53 02 00       call        0000000077BF16E0
      0000000077BCC358 8B C8                mov         ecx,eax
      0000000077BCC35A E8 71 14 0A 00       call        0000000077C6D7D0
      0000000077BCC35F CC                   int         3

      */

    ULONG Offset = 0;
    while (Offset < CodeLength) {

        ULONG Length = 0;

        if (0)
            ;

        // push ebp
        else if (IS_1BYTE(0x55))
            Length = 1;

        // mov ebp, esp
        else if (IS_2BYTE(0x8B, 0xEC))
            Length = 2;

        // mov edi, edi
        else if (IS_2BYTE(0x8B, 0xFF))
            Length = 2;

        // push ebx
        else if (IS_2BYTE(0xFF, 0xF3))
            Length = 2;

        // push rbx (Windows 8.1)
        else if (IS_2BYTE(0x40, 0x53))
            Length = 2;

        // mov dword ptr [esp+imm8],eax
        else if (IS_3BYTE(0x89, 0x44, 0x24))
            Length = 4;

        // lea eax, esp+imm8
        else if (IS_3BYTE(0x8D, 0x44, 0x24))
            Length = 4;

        // sub rsp, imm8
        else if (IS_3BYTE(0x48, 0x83, 0xEC))
            Length = 4;

        // mov rbx, rcx
        else if (IS_3BYTE(0x48, 0x8B, 0xD9))
            Length = 3;

        /*
        else if (IS_3BYTE(0x48, 0x8B, 0x04))
            inst_len = 4;
        */
        //
        // abort if we don't recognize the instruction
        //

        if (!Length) {

            return FALSE;
        }

        Offset += Length;
    }

#undef IS_3BYTE
#undef IS_2BYTE
#undef IS_1BYTE

    //
    // append a jump instruction at the bottom of our trampoline for
    // LdrInitializeThunk, which jumps back to the real LdrInitializeThunk
    //
    // note that on Windows 8 the difference between the address of
    // LdrInitializeThunk in the 64-bit ntdll and where SbieLow was copied
    // may be greater than 32-bit, so we use JMP QWORD rather than the
    // 5-byte 0xE9 relative JMP
    //
#ifdef _WIN64
    if (!Diff) {

        if (__Windows >= 10) {
            CodeData[Offset] = 0x48;
            CodeData[Offset + 1] = 0xE9;					// jmp
            *(ULONG*)&CodeData[Offset + 2] = (ULONG)
                (__LdrInitializeThunk + Offset - (VirtualAddress + Offset + 6));

        }
        else {
            CodeData[Offset] = 0xe9;
            *(ULONG*)&CodeData[Offset + 1] = (ULONG)
                (__LdrInitializeThunk + Offset - (VirtualAddress + Offset + 5));
        }
    }
    else {

        *(USHORT*)&CodeData[Offset] = 0x25FF;              // jmp qword ptr
        *(ULONG*)&CodeData[Offset + 2] = 0;
        *(ULONG64*)&CodeData[Offset + 6] = __LdrInitializeThunk + Offset;
    }
#else
    CodeData[Offset] = 0xE9;								// jmp 

    *(ULONG*)&CodeData[Offset + 1] = (ULONG)
        (__LdrInitializeThunk + Offset - (VirtualAddress + VirtualAddress + 5));
#endif

#endif

    return TRUE;
}
void* CopySyscalls(HANDLE ProcessHandle, BOOLEAN IsWow64
#ifdef _M_ARM64
    , BOOLEAN use_arm64ec
#endif
) {
    void* v5 = NULL;
    ULONG* v1;
#ifdef _M_ARM64
    if (use_arm64ec)
        v1 = m_syscall_ec_data;
    else
#endif
        v1 = __SyscallsData;
    SIZE_T ViewSize = *v1;

    v5 = AllocateRemoteMemory(ProcessHandle, ViewSize, FALSE
#ifdef _M_ARM64
        , FALSE
#endif
    );

    if (v5) {

        //
        // copy the syscall data buffer into the new process
        //

        SIZE_T Length1 = *v1;
        SIZE_T Length2 = 0;
        BOOL IsOk = WriteProcessMemory(
            ProcessHandle, v5, v1, Length1, &Length2);
        if (IsOk && Length1 == Length2) {

            return v5;
        }
    }

    return NULL;
}
BOOLEAN CopyData(
    HANDLE ProcessHandle, void* VirtualAddress, void* BufferData)
{
    //
    // copy SBIELOW_DATA data into the area reserved within SbieLow
    // (i.e. at offset SBIELOW_DATA_OFFSET) in the new process
    //

    void* v1 = (void*)((ULONG_PTR)VirtualAddress + __DataInfoOffset);
    SIZE_T Length1 = sizeof(_DATA_INFO_);
    SIZE_T Length2 = 0;
    BOOL IsOk = WriteProcessMemory(
        ProcessHandle, v1, BufferData, Length1, &Length2);
    if (IsOk && Length1 == Length2) {

        ULONG OldProtect;
        IsOk = VirtualProtectEx(ProcessHandle, VirtualAddress, __TestLength,
            PAGE_EXECUTE_READ, &OldProtect);
        if (IsOk) {
            return TRUE;
        }
    }

    return FALSE;
}


//Hook LdrInitializeThunk 指令跳转到汇编中
BOOLEAN WriteJump(HANDLE ProcessHandle, void* VirtualAddress, BOOLEAN Diff
#ifdef _M_ARM64
    , BOOLEAN use_arm64ec
#endif
) {
    //
    // prepare a short prolog code that jumps to the injected SbieLow
    //
    UCHAR ShellCode[20];
    void* v1 = (void*)VirtualAddress;
    UCHAR* OriginalAddress = (UCHAR*)((ULONG_PTR)__LdrInitializeThunk);
    SIZE_T Length1;
    BOOL IsOk;
    ULONG Protect;

#ifdef _M_ARM64

    if (use_arm64ec)
        func = (UCHAR*)((ULONG_PTR)m_LdrInitializeThunkEC);

    ULONG* aCode = (ULONG*)jump_code;
    //*aCode++ = 0xD43E0000;	// brk #0xF000
    *aCode++ = 0x58000048;	// ldr x8, 8
    *aCode++ = 0xD61F0100;	// br x8
    *(DWORD64*)aCode = (DWORD64)detour; aCode += 2;

    len1 = (UCHAR*)aCode - jump_code;

#elif _WIN64
    if (!Diff) 
    {
        if (__Windows >= 10) {
            Length1 = 6;
            ShellCode[0] = 0x48; //jump to entry code in entry.asm
            ShellCode[1] = 0xE9; //jump to entry code in entry.asm
            *(ULONG*)(ShellCode + 2) = (ULONG)((ULONG_PTR)v1 - (__LdrInitializeThunk + 6));
            //remote_addr = (void *)m_LdrInitializeThunk;
        }
        else {
            Length1 = 5;
            ShellCode[0] = 0xe9; //jump to entry code in entry.asm
            *(ULONG*)(ShellCode + 1) = (ULONG)((ULONG_PTR)v1 - (__LdrInitializeThunk + 5));
        }
    }

    else {
       
    }
#else
    Length1 = 5;
    ShellCode[0] = 0xE9; //jump to entry code in entry.asm
    *(ULONG*)(ShellCode + 1) = (ULONG)((ULONG_PTR)v1 - (__LdrInitializeThunk + 5));
    //remote_addr = (void *)m_LdrInitializeThunk;
#endif

     //
     // modify the bytes at LdrInitializeThunk with the prolog code
     //

    IsOk = VirtualProtectEx(ProcessHandle, OriginalAddress, Length1, PAGE_READWRITE, &Protect);
    if (IsOk) {
        SIZE_T Length2 = 0;
        IsOk = WriteProcessMemory(ProcessHandle, OriginalAddress, ShellCode, Length1, &Length2);
        /*
        sprintf(buffer,"WriteJump: len2 = %d\n",len2);
        OutputDebugStringA(buffer);
        */
        if (IsOk && Length1 == Length2) {
            IsOk = VirtualProtectEx(ProcessHandle, OriginalAddress, Length1, Protect, &Protect);
            if (IsOk) {
                return TRUE;
            }
        }
    }
    return FALSE;
}


#ifndef _M_ARM64
#ifdef _WIN64
BOOLEAN Has32BitJumpHorizon(void* Target, void* Detour)
{
    ULONG_PTR Diff1;
    long long Diff2;
    Diff1 = (ULONG_PTR)((ULONG_PTR)Target - (ULONG_PTR)Detour);
    Diff2 = Diff1;
    Diff2 < 0 ? Diff2 *= -1 : Diff2;
    //is DetourFunc in 32bit jump range
    if (Diff2 < 0x80000000) {
        return TRUE;
    }
    return FALSE;
}

#endif  //#ifdef _WIN64
#endif //#ifndef _M_ARM64


/*
0:000> u 00000000`00030011 l 30
00000000`00030011 4883ec28        sub     rsp,28h
00000000`00030015 48894c2420      mov     qword ptr [rsp+20h],rcx
00000000`0003001a 4889542428      mov     qword ptr [rsp+28h],rdx
00000000`0003001f 4c89442430      mov     qword ptr [rsp+30h],r8
00000000`00030024 4c894c2438      mov     qword ptr [rsp+38h],r9
00000000`00030029 e800000000      call    00000000`0003002e
00000000`0003002e 59              pop     rcx
00000000`0003002f 488bd9          mov     rbx,rcx
00000000`00030032 4881c140000000  add     rcx,40h
00000000`00030039 488bd3          mov     rdx,rbx
00000000`0003003c 4881c23e000000  add     rdx,3Eh
00000000`00030043 4c8bc3          mov     r8,rbx
00000000`00030046 4981c03e000000  add     r8,3Eh
00000000`0003004d e8aeffffff      call    00000000`00030000      EntryPointC
00000000`00030052 488b4c2420      mov     rcx,qword ptr [rsp+20h]
00000000`00030057 488b542428      mov     rdx,qword ptr [rsp+28h]
00000000`0003005c 4c8b442430      mov     r8,qword ptr [rsp+30h]
00000000`00030061 4c8b4c2438      mov     r9,qword ptr [rsp+38h]
00000000`00030066 4883c428        add     rsp,28h
00000000`0003006a ffe0            jmp     rax
00000000`0003006c 90              nop
00000000`0003006d 90              nop


*/