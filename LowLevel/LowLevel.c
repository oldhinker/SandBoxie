#include "LowLevel.h"
#include "MemoryHelper.h"
#include "InjectHelper.h"
/*
    0:007> u NtDeviceIoControlFile
    ntdll!ZwDeviceIoControlFile:
    00000000`77bf1320 4c8bd1          mov     r10,rcx
    00000000`77bf1323 b804000000      mov     eax,4
    00000000`77bf1328 0f05            syscall


    0:007> u NtProtectVirtualMemory
    ntdll!ZwProtectVirtualMemory:
    00000000`77bf17b0 4c8bd1          mov     r10,rcx
    00000000`77bf17b3 b84d000000      mov     eax,4Dh
    00000000`77bf17b8 0f05            syscall
    00000000`77bf17ba c3              ret

*/

#ifdef _M_ARM64
#else
ULONG_PTR __stdcall EntryPointC(DATA_INFO* DataInfo, void* DetourCode, void* SystemService)
#endif
{

    if (!DataInfo->IsInitializeDone)
    {
      
        EXTRA_DATA_INFO* ExtraDataInfo = NULL;
        SYSCALLS_DATA* SyscallsData = NULL;
      

        SyscallsData = (SYSCALLS_DATA*)DataInfo->SyscallsData;

        /*
        0:000> dq rdx
        00000000`00040000  00000ce0`00000ec0 00000031`b8d18b4c
        00000000`00040010  0000441f`0fc3050f 00000032`b8d18b4c
        00000000`00040020  0000441f`0fc3050f 00000004`b8d18b4c
        00000000`00040030  0000441f`0fc3050f 00000005`b8d18b4c
        00000000`00040040  0000441f`0fc3050f 000000c2`b8d18b4c
        00000000`00040050  0000441f`0fc3050f 000000c3`b8d18b4c
        00000000`00040060  0000441f`0fc3050f 0000004d`b8d18b4c
        00000000`00040070  0000441f`0fc3050f 0000004e`b8d18b4c
        
        */




        ExtraDataInfo = (EXTRA_DATA_INFO*)(DataInfo->SyscallsData + SyscallsData->ExtraDataInfoOffset);

        /*
        
        0:000> dd ebp
        00000000`00000ce0 

        0:000> dq rbp
        00000000`00040ce0  00000050`00000040 00000088`0000006c
        00000000`00040cf0  000000b8`0000009c 00000018`000000e4
        00000000`00040d00  00000068`000000fe 00000000`00000000
        00000000`00040d10  00000000`00000168 00000000`00000000
        00000000`00040d20  4464616f`4c72644c 00000000`00006c6c
        00000000`00040d30  72507465`4772644c 41657275`6465636f
        00000000`00040d40  00007373`65726464 7250744e`00000000
        00000000`00040d50  72695674`6365746f 6f6d654d`6c617574

        
        */




        volatile ULONG_PTR* Lock = &ExtraDataInfo->Lock;

#ifdef _WIN64
        ULONG_PTR OldLock = _InterlockedCompareExchange64(Lock, -1, 0);
#else ! _WIN64
        ULONG_PTR OldLock = _InterlockedCompareExchange(Lock, -1, 0);
#endif _WIN64

        if (OldLock == 0) 
        {

            /*
            0:000> dq rcx
            00000000`00030409  00000000`77ba0000 00000000`00040000
            00000000`00030419  00000000`00000004 12340036`00222007
            00000000`00030429  00000000`00000000 00000000`00000000
            00000000`00030439  02e920ec`8348f3ff 01b20000`0077b9bf
            00000000`00030449  00025388`e8cb8b48 cc000a14`71e8c88b
            00000000`00030459  90909090`90909090 90909090`90909090
            00000000`00030469  00000031`b8d18b4c 0000441f`0fc3050f
            00000000`00030479  00000032`b8d18b4c 0000441f`0fc3050f

            
            0:000> dq rdx
            00000000`0003035c  00000000`0000b848 e0988b4c`53570000
            00000000`0003036c  490fc380`41000000 c38349dc`8b4cdb8b
            00000000`0003037c  a8ec8148`fb8b4910 49084b89`49000000
            00000000`0003038c  4d184389`4d105389 68244c8d`48204b89
            00000000`0003039c  4dd08b4c`0851894c 41105989`4c085b8d
            00000000`000303ac  8d480189`481c428b 5024548d`48602444
            00000000`000303bc  20245489`48028948 24448948`18428b41
            00000000`000303cc  40b83024`4c894828 38244489`48000000

            0:000> u 00000000`0003035c l 30
            00000000`0003035c 48b80000000000000000 mov rax,0
            00000000`00030366 57              push    rdi
            00000000`00030367 53              push    rbx
            00000000`00030368 4c8b98e0000000  mov     r11,qword ptr [rax+0E0h]
            00000000`0003036f 4180c30f        add     r11b,0Fh
            00000000`00030373 498bdb          mov     rbx,r11
            00000000`00030376 4c8bdc          mov     r11,rsp
            00000000`00030379 4983c310        add     r11,10h
            00000000`0003037d 498bfb          mov     rdi,r11
            00000000`00030380 4881eca8000000  sub     rsp,0A8h
            00000000`00030387 49894b08        mov     qword ptr [r11+8],rcx
            00000000`0003038b 49895310        mov     qword ptr [r11+10h],rdx
            00000000`0003038f 4d894318        mov     qword ptr [r11+18h],r8
            00000000`00030393 4d894b20        mov     qword ptr [r11+20h],r9
            00000000`00030397 488d4c2468      lea     rcx,[rsp+68h]
            00000000`0003039c 4c895108        mov     qword ptr [rcx+8],r10
            00000000`000303a0 4c8bd0          mov     r10,rax
            00000000`000303a3 4d8d5b08        lea     r11,[r11+8]
            00000000`000303a7 4c895910        mov     qword ptr [rcx+10h],r11
            00000000`000303ab 418b421c        mov     eax,dword ptr [r10+1Ch]
            00000000`000303af 488901          mov     qword ptr [rcx],rax
            00000000`000303b2 488d442460      lea     rax,[rsp+60h]
            00000000`000303b7 488d542450      lea     rdx,[rsp+50h]
            00000000`000303bc 488902          mov     qword ptr [rdx],rax
            00000000`000303bf 4889542420      mov     qword ptr [rsp+20h],rdx
            00000000`000303c4 418b4218        mov     eax,dword ptr [r10+18h]
            00000000`000303c8 4889442428      mov     qword ptr [rsp+28h],rax
            00000000`000303cd 48894c2430      mov     qword ptr [rsp+30h],rcx
            00000000`000303d2 b840000000      mov     eax,40h
            00000000`000303d7 4889442438      mov     qword ptr [rsp+38h],rax
            00000000`000303dc 498b4a10        mov     rcx,qword ptr [r10+10h]
            00000000`000303e0 4833d2          xor     rdx,rdx
            00000000`000303e3 4c8bc2          mov     r8,rdx
            00000000`000303e6 4c8bca          mov     r9,rdx
            00000000`000303e9 4889542440      mov     qword ptr [rsp+40h],rdx
            00000000`000303ee 4889542448      mov     qword ptr [rsp+48h],rdx
            00000000`000303f3 4d8d9280000000  lea     r10,[r10+80h]
            00000000`000303fa 41ffd2          call    r10
            00000000`000303fd 4881c4a8000000  add     rsp,0A8h
            00000000`00030404 5b              pop     rbx
            00000000`00030405 5f              pop     rdi
            00000000`00030406 c3              ret

            */


            SyscallsPrepare(DataInfo, SystemService);


            /*
            if (!DataInfo->Flags.bHostInject && !DataInfo->Flags.bNoSysHooks)
                InitSyscalls(DataInfo, SystemService);
            */
            PrepareInjection(DataInfo, DetourCode);
        

#ifdef _WIN64
            if (DataInfo->Flags.is_wow64)
            {

#ifdef _M_ARM64
                if (!data->flags.is_chpe32)
                    DisableCHPE(data);
#endif
                if (!DataInfo->Flags.bNoConsole)
                {
                    //InitConsoleWOW64(data);
                }                  
            }
#endif

            // Set Init_Done 
            UCHAR IsInitializeDone = 1;
            
            WriteMemorySafe(DataInfo, &DataInfo->IsInitializeDone, sizeof(UCHAR), &IsInitializeDone);





#ifdef _WIN64
            _InterlockedExchange64(Lock, 1);
#else ! _WIN64
            _InterlockedExchange(Lock, 1);
#endif _WIN64

        }
       
    }


    /*
    00000000`00030356 4883c428        add     rsp,28h
    00000000`0003035a ffe0            jmp     rax {00000000`00030439}

    */
	return (ULONG_PTR)&DataInfo->LdrInitializeThunk_tramp;

    /*
    00000000`00030439 fff3            push    rbx
    00000000`0003043b 4883ec20        sub     rsp,20h
    00000000`0003043f e902bfb977      jmp     ntdll!LdrInitializeThunk+0x6 (00000000`77bcc346)
    00000000`00030444 0000            add     byte ptr [rax],al
    00000000`00030446 00b201488bcb    add     byte ptr [rdx-3474B7FFh],dh
    00000000`0003044c e888530200      call    00000000`000557d9
    00000000`00030451 8bc8            mov     ecx,eax
    00000000`00030453 e871140a00      call    00000000`000d18c9

    */
}



void SyscallsPrepare(DATA_INFO* DataInfo, void* SystemService)
{
#ifdef _M_ARM64
#endif
    {
        ULONG64 NtDeviceIoControlFile = (ULONG64)&DataInfo->NtDeviceIoControlFile_code[0];
        WriteMemorySafe(DataInfo, &DataInfo->NtDeviceIoControlFile, sizeof(ULONG64), &NtDeviceIoControlFile);

        /*
        0:000> u 00000000`00030489
        00000000`00030489 4c8bd1          mov     r10,rcx
        00000000`0003048c b804000000      mov     eax,4
        00000000`00030491 0f05            syscall





        0:000> dq rbx
        00000000`000304e9  00000000`00030489 00000000`00000000
        00000000`000304f9  00000000`77bf17b0 00000000`77bf25e0
        00000000`00030509  00000000`00000000 00000000`00000000



        DataInfo
        0:000> dq 30409 l 30
        00000000`00030409  00000000`77ba0000 00000000`00040000
        00000000`00030419  00000000`00000004 12340036`00222007
        00000000`00030429  00000000`00000000 00000000`00000000
        00000000`00030439  02e920ec`8348f3ff 01b20000`0077b9bf
        00000000`00030449  00025388`e8cb8b48 cc000a14`71e8c88b
        00000000`00030459  90909090`90909090 90909090`90909090
        00000000`00030469  00000031`b8d18b4c 0000441f`0fc3050f
        00000000`00030479  00000032`b8d18b4c 0000441f`0fc3050f
        00000000`00030489  00000004`b8d18b4c 0000441f`0fc3050f
        00000000`00030499  00000005`b8d18b4c 0000441f`0fc3050f
        00000000`000304a9  000000c2`b8d18b4c 0000441f`0fc3050f
        00000000`000304b9  000000c3`b8d18b4c 0000441f`0fc3050f
        00000000`000304c9  0000004d`b8d18b4c 0000441f`0fc3050f
        00000000`000304d9  0000004e`b8d18b4c 0000441f`0fc3050f
        00000000`000304e9  00000000`00030489 00000000`00000000
        00000000`000304f9  00000000`77bf17b0 00000000`77bf25e0
        00000000`00030509  00000000`00000000 00000000`00000000
        00000000`00030519  00000000`00000000 00000000`00000000

        
        */




    }

    const LONG OFFSET_ULONG_PTR =
#ifdef _M_ARM64
        - (LONG)sizeof(ULONG_PTR); // on arm64 windows we use a prepended data region
#elif _WIN64
        2;  // on 64-bit Windows, "mov rax, 0" instruction is two bytes
#else
        1;  // on 32-bit Windows, "mov edx, 0" instruction is one byte
#endif

    //
    // modify our assembly SystemService entry stub (in entry.asm)
    // to include the data area pointer
    //

    /*
    0:000> u 00000000`0003035c l 30
    00000000`0003035c 48b80904030000000000 mov rax,30409h
    00000000`00030366 57              push    rdi
    00000000`00030367 53              push    rbx
    00000000`00030368 4c8b98e0000000  mov     r11,qword ptr [rax+0E0h]
    00000000`0003036f 4180c30f        add     r11b,0Fh
    00000000`00030373 498bdb          mov     rbx,r11
    00000000`00030376 4c8bdc          mov     r11,rsp
    00000000`00030379 4983c310        add     r11,10h
    00000000`0003037d 498bfb          mov     rdi,r11
    00000000`00030380 4881eca8000000  sub     rsp,0A8h
    00000000`00030387 49894b08        mov     qword ptr [r11+8],rcx
    00000000`0003038b 49895310        mov     qword ptr [r11+10h],rdx
    00000000`0003038f 4d894318        mov     qword ptr [r11+18h],r8
    00000000`00030393 4d894b20        mov     qword ptr [r11+20h],r9
    00000000`00030397 488d4c2468      lea     rcx,[rsp+68h]
    00000000`0003039c 4c895108        mov     qword ptr [rcx+8],r10
    00000000`000303a0 4c8bd0          mov     r10,rax
    00000000`000303a3 4d8d5b08        lea     r11,[r11+8]
    00000000`000303a7 4c895910        mov     qword ptr [rcx+10h],r11
    00000000`000303ab 418b421c        mov     eax,dword ptr [r10+1Ch]
    00000000`000303af 488901          mov     qword ptr [rcx],rax
    00000000`000303b2 488d442460      lea     rax,[rsp+60h]
    00000000`000303b7 488d542450      lea     rdx,[rsp+50h]
    00000000`000303bc 488902          mov     qword ptr [rdx],rax
    00000000`000303bf 4889542420      mov     qword ptr [rsp+20h],rdx
    00000000`000303c4 418b4218        mov     eax,dword ptr [r10+18h]
    00000000`000303c8 4889442428      mov     qword ptr [rsp+28h],rax
    00000000`000303cd 48894c2430      mov     qword ptr [rsp+30h],rcx
    00000000`000303d2 b840000000      mov     eax,40h
    00000000`000303d7 4889442438      mov     qword ptr [rsp+38h],rax
    00000000`000303dc 498b4a10        mov     rcx,qword ptr [r10+10h]
    00000000`000303e0 4833d2          xor     rdx,rdx
    00000000`000303e3 4c8bc2          mov     r8,rdx
    00000000`000303e6 4c8bca          mov     r9,rdx
    00000000`000303e9 4889542440      mov     qword ptr [rsp+40h],rdx
    00000000`000303ee 4889542448      mov     qword ptr [rsp+48h],rdx
    00000000`000303f3 4d8d9280000000  lea     r10,[r10+80h]
    00000000`000303fa 41ffd2          call    r10
    00000000`000303fd 4881c4a8000000  add     rsp,0A8h
    00000000`00030404 5b              pop     rbx
    00000000`00030405 5f              pop     rdi
    00000000`00030406 c3              ret

    
    */

    WriteMemorySafe(DataInfo, ((UCHAR*)SystemService) + OFFSET_ULONG_PTR, sizeof(ULONG_PTR), &DataInfo);

    //
    // store the SystemService address in pSystemService
    //

    ULONG64 v1 = (ULONG64)SystemService;
    WriteMemorySafe(DataInfo, &DataInfo->SystemService, sizeof(ULONG64), &v1);


    /*
    0:000> dq rbx
    00000000`00030509  00000000`0003035c 00000000`00000000


    0:000> u 0003035c
    00000000`0003035c 48b80904030000000000 mov rax,30409h
    00000000`00030366 57              push    rdi
    00000000`00030367 53              push    rbx
    00000000`00030368 4c8b98e0000000  mov     r11,qword ptr [rax+0E0h]
    00000000`0003036f 4180c30f        add     r11b,0Fh
    00000000`00030373 498bdb          mov     rbx,r11
    00000000`00030376 4c8bdc          mov     r11,rsp
    00000000`00030379 4983c310        add     r11,10h

    */
}