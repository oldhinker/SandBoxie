#include "HookHelper.h"
#include "StatusHelper.h"
#include "Trampoline.h"
#include "MemoryHelper.h"
#include "dllmain.h"

LIST __ModuleHooks;
CRITICAL_SECTION  __CriticalSection;



void InitializeModuleHook()
{
    InitializeCriticalSection(&__CriticalSection);
    InitializeList(&__ModuleHooks);

    //Dll_HookTrace = SbieApi_QueryConfBool(NULL, L"HookTrace", FALSE);

#ifdef _M_ARM64EC

#endif
}






void* ModuleHook(
    const char* SeviceName, void* ServiceAddress, void* DetourAddress, HMODULE Module)
{

    /*
    0:000> u 00000000`77bf13b0
ntdll!NtQueryObject:
00000000`77bf13b0 4c8bd1          mov     r10,rcx
00000000`77bf13b3 b80d000000      mov     eax,0Dh
00000000`77bf13b8 0f05            syscall
00000000`77bf13ba c3              ret
00000000`77bf13bb 0f1f440000      nop     dword ptr [rax+rax]

    
    */



    DWORD HookStats = 0;
    void* v5 = NULL;
    PDWORD64 v10 = NULL;
    if (0)
    {
       
        goto Exit;
    }

    if (0)
    {

    }

   
    v5 = InstallModuleHook(SeviceName, ServiceAddress, DetourAddress, Module, &HookStats);

    if (v10) {
        *v10 = (DWORD64)v5;
        v5 = NULL;
    }
Exit:
    return v5;
}

void* InstallModuleHook(
    const char* SeviceName, void* ServiceAddress, void* DetourAddress, HMODULE Module, DWORD* HookStats)
{


    if (0)
    {


    }
#ifdef _M_ARM64EC

#endif
#ifdef _M_ARM64
  
#else
    return InstallModuleHookInternal(SeviceName, ServiceAddress, DetourAddress, Module);
#endif
}


void* InstallModuleHookInternal(
    const char* SeviceName, void* ServiceAddress, void* DetourAddress, HMODULE Module)
{
    UCHAR* Trampoline, * v1 = NULL;
    void* RegionBase;
    SIZE_T RegionSize;
    ULONG OldProtect;
    ULONG_PTR Offset;
    ULONG_PTR TargetAddress;
#ifdef _WIN64
    long long Delta;
    BOOLEAN CallInstruction64 = FALSE;
#endif _WIN64



    if (!ServiceAddress) {
       
        return NULL;
    }

    if (*(UCHAR*)ServiceAddress == 0xEB) { // jmp xx;
        signed char Offset = *((signed char*)ServiceAddress + 1);    //获取偏移
        ServiceAddress = (UCHAR*)ServiceAddress + Offset + 2;        //获取目的地
    }

    while (*(UCHAR*)ServiceAddress == 0xE9) { // jmp xx xx xx xx;

        Offset = *(LONG*)((ULONG_PTR)ServiceAddress + 1);
        TargetAddress = (ULONG_PTR)ServiceAddress + Offset + 5;
        if (TargetAddress == (ULONG_PTR)DetourAddress) 
        {
            return NULL;
        }

#ifdef _WIN64

        ServiceAddress = (void*)TargetAddress;
#else ! WIN_64

#endif _WIN64

    }
#ifdef _WIN64
    if (*(USHORT*)ServiceAddress == 0xE990) { // nop; jmp xx xx xx xx;
        Offset = *(LONG*)((ULONG_PTR)ServiceAddress + 2);
        TargetAddress = (ULONG_PTR)ServiceAddress + Offset + 6;
        if (*(USHORT*)TargetAddress == 0x25FF) // jmp QWORD PTR [rip+xx xx xx xx];
            ServiceAddress = (void*)TargetAddress;
    }

#if 0
#endif

#endif _WIN64

    //申请Hook信息内存
    MODULE_HOOK* ModuleHook = GetModuleHookInfo(Module, POOL_TAG | 0xFF); // 0xFF - executable
    if (!ModuleHook) {
       
        goto Exit;
    }
#ifdef _WIN64
    if (*(USHORT*)ServiceAddress == 0x15FF) { // call QWORD PTR [rip+xx xx xx xx];
    
        UCHAR* NewDetour = (UCHAR*)MemoryPoolAllocateEx(ModuleHook->Pool, 128);
        if (!NewDetour) {
         
            goto Exit;
        }
    
        NewDetour[0] = 0x58;        // pop rax
        NewDetour[1] = 0x48;        // mov rax, DetourFunc
        NewDetour[2] = 0xB8;
        *(ULONG_PTR*)(&NewDetour[3]) = (ULONG_PTR)DetourAddress;
        NewDetour[11] = 0xFF;       // jmp rax
        NewDetour[12] = 0xE0;

        DetourAddress = NewDetour;


        NewDetour[16] = 0x48;       // mov rax, ServiceAddress+6
        NewDetour[17] = 0xB8;
        *(ULONG_PTR*)(&NewDetour[18]) = (ULONG_PTR)ServiceAddress + 6;
        NewDetour[26] = 0x50;       // push rax
        NewDetour[27] = 0x48;       // mov rax, trampoline code
        NewDetour[28] = 0xB8;
        *(ULONG_PTR*)(&NewDetour[29]) = 0;
        NewDetour[37] = 0xFF;       // jmp rax
        NewDetour[38] = 0xE0;


        CallInstruction64 = TRUE;

        //
        // overwrite the code at the target of the call instruction
        //

        Offset = *(LONG*)((ULONG_PTR)ServiceAddress + 2);
        TargetAddress = (ULONG_PTR)ServiceAddress + 6 + Offset;
        ServiceAddress = (void*)*(ULONG_PTR*)TargetAddress;

    }
#endif _WIN64
    Trampoline = (UCHAR*)MemoryPoolAllocateEx(ModuleHook->Pool, 128);
    if (!Trampoline /*|| !VirtualProtect(tramp, 128, PAGE_EXECUTE_READWRITE, &dummy_prot)*/) {
     
        goto Exit;
    }

    if (CreateModuleHookTrampoline(ServiceAddress, Trampoline) != 0) {
       
        goto Exit;
    }

    v1 = (UCHAR*)ServiceAddress;

    RegionBase = &v1[-8]; // -8 for hotpatch area if present
    RegionSize = 20;

    if (!VirtualProtect(RegionBase, RegionSize, PAGE_EXECUTE_READWRITE, &OldProtect)) {

        //
        // on windows 7 hooking NdrClientCall2 in 32bit (WoW64) mode fails
        // because the memory area starts at -6 and not -8
        // this area could be a hot patch reagion which we don't use
        // hence if that fails just start at the exact offset and try again
        //

        RegionBase = &v1[0];
        RegionSize = 12;

        if (!VirtualProtect(RegionBase, RegionSize, PAGE_EXECUTE_READWRITE, &OldProtect)) {
            ULONG LastError = GetLastError();
        
            v1 = NULL;
            goto Exit;
        }
    }

#ifdef _WIN64
    if (__Windows >= 10) 
    {
        TargetAddress = (ULONG_PTR)&v1[6];
    }
    else {
        TargetAddress = (ULONG_PTR)&v1[5];
    }

    Offset = (ULONG_PTR)((ULONG_PTR)DetourAddress - TargetAddress);
    Delta = Offset;
    Delta < 0 ? Delta *= -1 : Delta;

    //is DetourFunc in 32bit jump range
    if (Delta < 0x80000000) {
        /*
        sprintf(buffer,"32 bit Hook: %s\n",SourceFuncName);
        OutputDebugStringA(buffer);
        */
        if (__Windows >= 10) {
            v1[0] = 0x48;             // 32bit relative rex.W JMP DetourFunc
            v1[1] = 0xE9;
            *(ULONG*)(&v1[2]) = (ULONG)Offset;
            //UsedCount = 1 + 1 + 4;
        }
        else {
            v1[0] = 0xE9;             // 32bit relative JMP DetourFunc
            *(ULONG*)(&v1[1]) = (ULONG)Offset;
            //UsedCount = 1 + 4;
        }
    }

    //is DetourFunc in 64bit jump range
    /*else if (1) {

        func[0] = 0x48;
        func[1] = 0xb8;
        *(ULONG_PTR *)&func[2] = (ULONG_PTR)DetourFunc;
        func[10] = 0xff;
        func[11] = 0xe0;
    }*/

    else {

        TargetAddress = (ULONG_PTR)&v1[6];

        /*
        0:000> u 00000000`77bf13b6
ntdll!NtQueryObject+0x6:
00000000`77bf13b6 0000            add     byte ptr [rax],al
00000000`77bf13b8 0f05            syscall
        */



        VECTOR_TABLE* VTable = GetHookTable(ModuleHook, TargetAddress, 0x80000000, TRUE);
        if (!VTable) {
            // OutputDebugStringA("Memory alloc failed: 12 Byte Patch Disabled\n");
    
            v1 = NULL;
            goto Exit;
        }

        Offset = (ULONG_PTR) & ((ULONG_PTR*)VTable->Offset)[VTable->Index];
        Offset = Offset - TargetAddress;

        ((ULONG_PTR*)VTable->Offset)[VTable->Index] = (ULONG_PTR)DetourAddress;
        *(USHORT*)&v1[0] = 0x25ff;       // jmp QWORD PTR [rip+diff];
        *(ULONG*)&v1[2] = (ULONG)Offset;
        //UsedCount = 2 + 4;
        VTable->Index++;
    }

#else
    Offset = (UCHAR*)DetourAddress - (v + 5);
    v1[0] = 0xE9;             // JMP DetourFunc
    *(ULONG*)(&v1[1]) = (ULONG)Offset;
    //UsedCount = 1 + 4;
#endif


    VirtualProtect(RegionBase, RegionSize,OldProtect, &OldProtect);

    // the trampoline code begins at trampoline + 16 bytes
    v1 = (UCHAR*)(ULONG_PTR)(Trampoline + 16);
    /*
    0:000> u 000007ff`fff80218
000007ff`fff80218 4c8bd1          mov     r10,rcx
000007ff`fff8021b b80d000000      mov     eax,0Dh
000007ff`fff80220 0f05            syscall
000007ff`fff80222 c3              ret
    
    */



#ifdef _WIN64

    if (CallInstruction64) {

        UCHAR* NewDetour = (UCHAR*)DetourAddress;
        *(ULONG_PTR*)(&NewDetour[29]) = (ULONG_PTR)v1;    //跳回源函数之后指令
        v1 = NewDetour + 16;
    }

#endif _WIN64
Exit:

    LeaveCriticalSection(&__CriticalSection);

    return v1;


}



MODULE_HOOK* GetModuleHookInfo(HMODULE Module, ULONG Tag)
{
    //
    // Get the module hook resource for this module, if module is NULL
    // its NTDLL or a special case
    //

    EnterCriticalSection(&__CriticalSection);

    MODULE_HOOK* v1 = (MODULE_HOOK*)GetListHead(&__ModuleHooks);
    while (v1) {

        if (v1->Module == Module
#ifdef _M_ARM64EC
            && mod_hook->tag == tag
#endif
            )
            break;

        v1 = (MODULE_HOOK*)GetNextNode(v1);
    }

    if (!v1) {
        v1 = (MODULE_HOOK*)MemoryPoolAllocateEx(__Pool,sizeof(MODULE_HOOK));
        if (!v1)
            return NULL;
        v1->Module = Module;
#ifdef _M_ARM64EC
        mod_hook->tag = tag;
#endif
        v1->Pool = NULL;
#ifdef _WIN64
        InitializeList(&v1->VTables);
#endif
        InitializeList(&v1->Trace);
        InsertBefore(&__ModuleHooks, NULL, v1); // insert first as we probably will use it often in the next few calls
    }
    if (!v1->Pool){
        v1->Pool = CreateMemoryPoolWithTagged(Tag);
        if (!v1->Pool)
            return NULL;
    }

    return v1;
}


void UninstallModuleHook(HMODULE Module)
{
    EnterCriticalSection(&__CriticalSection);

    MODULE_HOOK* ModuleHook = (MODULE_HOOK*)GetListHead(&__ModuleHooks);
    while (ModuleHook) {

        MODULE_HOOK* Next = (MODULE_HOOK*)GetNextNode(ModuleHook);

        if (ModuleHook->Module == Module) {

            RemoveCurrent(&__ModuleHooks, ModuleHook);

#ifdef _WIN64
            VECTOR_TABLE* VTable = (VECTOR_TABLE*)GetListHead(&ModuleHook->VTables);
            while (VTable) {

                if (VTable->Offset)
                    VirtualFree(VTable->Offset, 0, MEM_RELEASE);

                VTable = (VECTOR_TABLE*)GetNextNode(VTable);
            }
#endif

            DeleteMemoryPool(ModuleHook->Pool);
            FreeHookModuleInfo(ModuleHook);

            // we may have more then one entry with different tags on ARM64
#ifndef _M_ARM64EC
            break;
#endif
        }

        ModuleHook = Next;
    }

    LeaveCriticalSection(&__CriticalSection);
}
void FreeHookModuleInfo(void* ModuleHook)
{
    UCHAR* v1 = ((UCHAR*)ModuleHook) - sizeof(ULONG_PTR);
    ULONG ViewSize = (ULONG)(*(ULONG_PTR*)v1);

#ifdef DEBUG_MEMORY
    {
        //WCHAR txt[64];
        int i;
        UCHAR* Previous = v1 - 64;
        UCHAR* Post = v1 + ViewSize - 64 * 2;
        for (i = 0; i < 64; ++i)
            if (Previous[i] != 0xCC || Post[i] != 0xCC) {
          
                while (!IsDebuggerPresent()) Sleep(500);
                __debugbreak();
            }

        v1 -= 64;
        //Sbie_snwprintf(txt, 64, L"Dll_Free  for %-6d        at %08X\n", size, ptr2);
        //OutputDebugString(txt);
    }
#endif // DEBUG_MEMORY

    MemoryPoolFree(v1, ViewSize);

#ifdef DEBUG_MEMORY
  
#endif // DEBUG_MEMORY
}

LONG CreateModuleHookTrampoline(void* ServiceAddress, void* Trampoline)
{
    NTSTATUS Status;
#ifdef _WIN64
    BOOLEAN Is64 = TRUE;
#else
    BOOLEAN Is64 = FALSE;
#endif _WIN64

    if (BuildHookTrampoline(ServiceAddress, Trampoline, Is64, TRUE))
        Status = STATUS_SUCCESS;
    else
        Status = STATUS_UNSUCCESSFUL;

    return Status;
}


#ifdef _WIN64
VECTOR_TABLE* GetHookTable(MODULE_HOOK* ModuleHook, ULONG_PTR TargetAddress, __int64 MaxDelta, BOOLEAN LongRange)
{

    VECTOR_TABLE* VTable = (VECTOR_TABLE*)GetListHead(&ModuleHook->VTables);
    BOOLEAN DefaultRange = FALSE;
    ULONG_PTR Diff;
    __int64 Delta;
    for (;;) 
    {
        if (!VTable || !VTable->Offset)
        { // if there is no vtable create it
            ULONG_PTR v1;
            ULONG_PTR Step = 0x20000;// + VTABLE_SIZE;
            ULONG_PTR Max = 0x4000000 / Step;

            // optimization for windows 7 and low memory DLL's
            if (TargetAddress < 0x80000000 && (TargetAddress > 0x4000000)) {
                Step = 0x200000;
            }
            // optimization for windows 8.1
            else if (TargetAddress < 0x4000000)
            {
                Step *= -1;
            }
            else if (TargetAddress < 0x10000000000) {
                Step *= -1;
            }
            else if (LongRange) {
                DefaultRange = TRUE;
            }

            // sprintf(buffer,"VTable Alloc: target = %p, step = %p, default = %d\n",target,step,defaultRange);
            // OutputDebugStringA(buffer);
            v1 = (TargetAddress & 0xfffffffffffe0000) - (Step << 2);

            if (DefaultRange) {
                v1 -= 0x20000000;
            }

            if (!VTable) {

                VTable = (VECTOR_TABLE*)MemoryPoolAllocate(ModuleHook->Pool, sizeof(VECTOR_TABLE));
                if (!VTable) {
          
                    break;
                }

                memset(VTable, 0, sizeof(VECTOR_TABLE));

                InsertAfter(&ModuleHook->VTables, NULL, VTable);
            }

            for (; !VTable->Offset && Max; v1 -= Step, Max--) {

                PVOID RegionBase = (PVOID)v1;
                SIZE_T RegionSize = VTABLE_SIZE;
#ifdef  _M_ARM64EC
        
#else
                if (NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &RegionBase, 0, &RegionSize, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE)))
                    VTable->Offset = RegionBase;
#endif
                //ptrVTable->offset = VirtualAlloc((void*)tempAddr, VTABLE_SIZE, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE); // PAGE_READWRITE
                //  sprintf(buffer,"VTable Offset: target = %p, offset = %p, tryAddress = %p, attempt = 0x%x\n",target,ptrVTable->offset,tempAddr,max_attempts);
                //  OutputDebugStringA(buffer);
            }

            // brute force fallback
            if (!VTable->Offset) {

                Step = VTABLE_SIZE;
                Max = 0x40000000 / Step; // 1 gig
                ULONG_PTR v2 = 0;

                v1 = ((ULONG_PTR)TargetAddress & 0xfffffffffffe0000);

                for (; !VTable->Offset && v2 < (Max * 2); v2++) {

                    ULONG_PTR v3 = v1 + (((v2 + 2) / 2) * Step);
                    if ((v2 % 2) == 0) // search both directions alternating
                        v3 *= -1;

                    PVOID RegionBase = (PVOID)v3;
                    SIZE_T RegionSize = VTABLE_SIZE;
#ifdef  _M_ARM64EC
          
#else
                    if (NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &RegionBase, 0, &RegionSize, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE)))
                        VTable->Offset = RegionBase;
#endif
                }
            }

            VTable->Index = 0;
            VTable->MaxEntries = VTABLE_SIZE / sizeof(void*);
        }

        if (VTable && VTable->Offset) { // check if we have a vtable

            // the table is not full
            if (VTable->Index < VTable->MaxEntries) {

                Diff = (ULONG_PTR) & ((ULONG_PTR*)VTable->Offset)[VTable->Index];
                Diff = Diff - TargetAddress;
                Delta = Diff;
                Delta < 0 ? Delta *= -1 : Delta;

                // is DetourFunc in the jump range
                if (Delta < MaxDelta && VTable->Index <= VTable->MaxEntries) {
                    // found a good table, break and return it
                    break;
                }
            }
        }
        else { // fail and disable vtable if it could not be initialized
            //SbieApi_Log(2303, _fmt1, SourceFuncName, 888);
            VTable = NULL;
            break;
        }

        VTable =(VECTOR_TABLE*)GetNextNode(VTable);

    }




    return VTable;


}
#endif _WIN64