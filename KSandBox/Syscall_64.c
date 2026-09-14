#pragma once
#include "Syscall.h"

#include "SystemHelper.h"

#pragma pack(push)
#pragma pack(1)


typedef struct _SYSTEM_SERVICE_DESCRIPTOR_ {

    LONG* Base;
    ULONG* DontCare1;   // always zero?
    ULONG Limit;
    LONG DontCare2;     // always zero?
    UCHAR* DontCare3;

}SYSTEM_SERVICE_DESCRIPTOR,*PSYSTEM_SERVICE_DESCRIPTOR;


#pragma pack(pop)


ULONG GetSystemServiceIndex(UCHAR* ServiceAddress)
{
    ULONG ServiceIndex = -1;

#ifdef _M_ARM64

    SVC svc;
    svc.OP = *(ULONG*)code;

    if (IS_SVC(svc))
        ServiceIndex = svc.imm16;

#else

    if (ServiceAddress[0] == 0x4C && ServiceAddress[1] == 0x8B && ServiceAddress[2] == 0xD1)
        ServiceAddress += 3;                          // skip mov r10, rcx

    if (*ServiceAddress == 0xB8)                      // mov eax, syscall number
        ServiceIndex = *(ULONG*)(ServiceAddress + 1);

#endif

    if (ServiceIndex == -1)
    {

    }

    return ServiceIndex;
}
void* GetSystemServiceTable(void)
{
    static SYSTEM_SERVICE_DESCRIPTOR* ShadowSsTable = NULL;    //sssdt
    SYSTEM_SERVICE_DESCRIPTOR* Ssdt;   //ssdt

    if (ShadowSsTable)
        return ShadowSsTable;

    if (0) {

        ULONG_PTR NtosKrnl = GetNtosKrnl();
        if (!NtosKrnl)
            return NULL;
    }

    //
    // the shadow table should be 0x40 bytes before the master table,
    // on Windows XP (64-bit),
    // and 0x40 bytes after the master table, on Windows Vista (64-bit)
    //     0xC0 bytes after the master table, on    Vista SP 2 (64-bit)
    //

    Ssdt = (SYSTEM_SERVICE_DESCRIPTOR*)GetSystemServiceTableInternal();

    if (!Ssdt)
    {
      
        return NULL;
    }
   
    if (__OsBuild >= 17682) {
       
    }
    else if (__OsBuild >= 9800) {
       
    }
    else
    {

        /*
        kd> dq fffff800`03e03000+2AD940
fffff800`040b0940  fffff800`03e79800 00000000`00000000    Ssdt   NtosKrnl.exe  CreateProcess CreateThread
fffff800`040b0950  00000000`00000191 fffff800`03e7a48c

fffff800`040b0960  00000000`00000000 00000000`00000000
fffff800`040b0970  00000000`00000000 00000000`00000000


fffff800`040b0980  fffff800`03e79800 00000000`00000000  Ssdt
fffff800`040b0990  00000000`00000191 fffff800`03e7a48c
fffff800`040b09a0  fffff960`000e1f00 00000000`00000000  ShadowSsdt    Win32k.sys  SendMesage  PostMessage  
fffff800`040b09b0  00000000`0000033b fffff960`000e3c1c

        
        
        */
        ShadowSsTable = (SYSTEM_SERVICE_DESCRIPTOR*)((ULONG_PTR)Ssdt + 0x40);
        if (ShadowSsTable->Base != Ssdt->Base) {
            ShadowSsTable = (SYSTEM_SERVICE_DESCRIPTOR*)((ULONG_PTR)Ssdt + 0xC0);
        }
        if (ShadowSsTable->Base != Ssdt->Base) {
            ShadowSsTable = (SYSTEM_SERVICE_DESCRIPTOR*)((ULONG_PTR)Ssdt + 0x2C0);
        }
    }
    if (ShadowSsTable->Base != Ssdt->Base) {

      
        ShadowSsTable = NULL;
    }


    return ShadowSsTable;
}
void* GetSystemServiceTableInternal(void)
{
    NTSTATUS Status;
    void* Ssdt;

    UNICODE_STRING v1;
    UCHAR* v2;
    ULONG i;
    ULONG_PTR NtosKrnl;
    ULONG Offset32a;
    ULONG Offset32b;

    //
    // if NTOSKRNL exports KeServiceDescriptorTable, use that
    //


    //某些系统中Ssdt表是以全部变量的身份被NtosKrnl.exe导出的


    /*
    kd> dq KeServiceDescriptorTable
fffff800`040b0940  fffff800`03e79800 00000000`00000000
fffff800`040b0950  00000000`00000191 fffff800`03e7a48c

    
    */
    RtlInitUnicodeString(&v1, L"KeServiceDescriptorTable");
    Ssdt = MmGetSystemRoutineAddress(&v1);

    if (Ssdt)
        return Ssdt;

    // else we find it ourselves.  first find where the NT kernel was loaded.
    // this may be variable on Vista
    //

    NtosKrnl = GetNtosKrnl();
    if (!NtosKrnl)
        return NULL;

    //
    // next, analyze KeAddSystemServiceTable to learn where shadow table is
    //

    RtlInitUnicodeString(&v1, L"KeAddSystemServiceTable");
    v2 = (UCHAR*)MmGetSystemRoutineAddress(&v1);
    if (!v2)
        return NULL;

#ifdef _M_ARM64

   
#else

    //MasterTable lookup for windows 11 insider 22563 or server 2022 20348
    if (__OsBuild >= 20348) {

      
    }

    //MasterTable lookup for windows 10
    if (__OsBuild >= 10041) {

       
    }

    //MasterTable lookup for windows 7 and 8
    else {

        ULONG_PTR v5, v3;

        v5 = NtosKrnl;
        v3 = 0;

        for (i = 0; i < 32; ++i) {
            if (*v2 == 0x4C || *v2 == 0x48) {
                Offset32a = *(ULONG*)&v2[3];
                v3 = (ULONG_PTR)(v2 + 7 + (LONG_PTR)(LONG)Offset32a);
                if (v3 == v5) {
                    v2 += 7;
                    break;
                }
                v3 = 0;
}
            ++v2;
        }
        //fffff800`041ebc4c 4c8d1dad73c1ff  lea     r11,[nt!KiSelectNextThread <PERF> (nt+0x0) (fffff800`03e03000)]
        //
        if (v5 != v3)
            return NULL;

        Offset32a = -1;
        Offset32b = -1;

        for (i = 0; i < 32; ++i) {
            if ((v2[0] == 0x4A || v2[0] == 0x4B) &&
                v2[1] == 0x83 && v2[8] == 0x00)
            {
                if (Offset32a == -1)
                    Offset32a = *(ULONG*)&v2[4];
                else if (Offset32b == -1) {
                    Offset32b = *(ULONG*)&v2[4];
                    break;
                }
            }
            ++v2;
        }

        if (Offset32a >= 0x400000 || Offset32b >= 0x400000) {

            //
            // alternatively on Windows 8: expect "cmp [rax+rbx+ofs32],0"
            // followed by "lea rcx,[rbx+ofs32]
            //

            int v10 = 0;
        }
        if (Offset32a >= 0x400000 || Offset32b >= 0x400000)
            return NULL;



        Ssdt = (void*)(v5 + Offset32a);

        /*
        kd> dq fffff800`03e03000+2AD940
fffff800`040b0940  fffff800`03e79800 00000000`00000000
fffff800`040b0950  00000000`00000191 fffff800`03e7a48c

        */

        return Ssdt;
    }
#endif

    return 0;
}

BOOLEAN GetSystemServiceAddress(ULONG ServiceIndex, void** ServiceAddress, ULONG* ParameterCount)
{
    PSYSTEM_SERVICE_DESCRIPTOR ShadowSsTable =
        (PSYSTEM_SERVICE_DESCRIPTOR)GetSystemServiceTable();
    if (ShadowSsTable)
    {

        /*
      
        typedef struct _SYSTEM_SERVICE_DESCRIPTOR_ {
            LONG* Base;
            ULONG* DontCare1;   // always zero?
            ULONG Limit;
            LONG DontCare2;     // always zero?
            UCHAR* DontCare3;
        }SYSTEM_SERVICE_DESCRIPTOR,*PSYSTEM_SERVICE_DESCRIPTOR;

    

        fffff800`040b0980  fffff800`03e79800 00000000`00000000  Ssdt
        fffff800`040b0990  00000000`00000191 fffff800`03e7a48c
        fffff800`040b09a0  fffff960`000e1f00 00000000`00000000  ShadowSsdt    Win32k.sys  SendMesage  PostMessage
        fffff800`040b09b0  00000000`0000033b fffff960`000e3c1c
*/


        ULONG Limit = ShadowSsTable->Limit;
        if ((ServiceIndex < 0x1000) &&
            ((ServiceIndex & 0xFFF) < Limit))
        {

            LONG_PTR EntryValue = (LONG_PTR)ShadowSsTable->Base[ServiceIndex];

            /*
           kd> dd fffff800`03e79800
        fffff800`03e79800  04134b00 02f53600 fff6f000 02e80205
        fffff800`03e79810  031c3b06 0312ba05 02bacc01 02b49200
        fffff800`03e79820  03143840 03e32500 02c6fe00 02e75b40
        fffff800`03e79830  02f65c00 02df5601 02dc3901 02d81d00
        fffff800`03e79840  02de7902 02f15e00 02accd40 02cdbb01
        fffff800`03e79850  02ceda02 02f67402 03116001 0322d801
        fffff800`03e79860  045b7805 02ecf740 02b28883 ffeb5c00
        fffff800`03e79870  0441dc00 02f4ea40 02c3e201 0313d800

            */


            //04134b0 + fffff800`03e79800

            /*
            kd> u fffff800`03e79800+ 04134b0
        nt!NtMapUserPhysicalPagesScatter:
        fffff800`0428ccb0 48895c2408      mov     qword ptr [rsp+8],rbx
        fffff800`0428ccb5 4c89442418      mov     qword ptr [rsp+18h],r8
        fffff800`0428ccba 55              push    rbp
        fffff800`0428ccbb 56              push    rsi
        fffff800`0428ccbc 57              push    rdi
        fffff800`0428ccbd 4154            push    r12
        fffff800`0428ccbf 4155            push    r13
        fffff800`0428ccc1 4156            push    r14
        kd> u fffff800`03e79800+ 02e8020
        nt!NtReadFile:
        fffff800`04161820 4c8bdc          mov     r11,rsp
        fffff800`04161823 4d894b20        mov     qword ptr [r11+20h],r9
        fffff800`04161827 4d894318        mov     qword ptr [r11+18h],r8
        fffff800`0416182b 49895310        mov     qword ptr [r11+10h],rdx

            */
            *ServiceAddress = (UCHAR*)ShadowSsTable->Base + (EntryValue >> 4);

            //02e80205 & 000000001111
#ifdef _M_ARM64
            * ParameterCount = (ULONG)(EntryValue & 0x0F) + 8;
#else
            * ParameterCount = (ULONG)(EntryValue & 0x0F) + 4;
#endif
            return TRUE;
        }
    }

    return FALSE;
}
