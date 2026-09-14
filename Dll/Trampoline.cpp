#include "Trampoline.h"
#include "InstructionAnalyze.h"
#include "MemoryPool.h"


void* BuildHookTrampoline(
    void* ServiceAddress, void* Trampoline, BOOLEAN Is64, BOOLEAN IsProbe)
{
    ULONG ByteCount;
    TRAMPOLINE* v1 = NULL;


   
    if (ServiceAddress) {
        if (!GetTrampolineLength(ServiceAddress, &ByteCount, Is64, IsProbe))
            return NULL;
    }

#ifdef KERNEL_MODE

#endif
    v1 = (TRAMPOLINE*)Trampoline;
    if (!v1)
        return NULL;

    if (ServiceAddress) {
        if (!GetTrampolienCode(v1, ServiceAddress, ByteCount, Is64, IsProbe))
            return NULL;
    }
    
    return &v1->CodeData;
}


BOOLEAN GetTrampolineLength(
    void* ServiceAddress, ULONG* ByteCount, BOOLEAN Is64, BOOLEAN IsProbe)
{
    UCHAR* v1 = (UCHAR*)ServiceAddress;
    ULONG Length1 = (Is64 ? 12 : 5);
    ULONG Length2 = 0;

    // count at least the (needlen) bytes of instructions from the original
    // entry point to our stub, as we will overwrite that area later

    while (1) {

        _INSTRUCTION_ Instruction;
        BOOLEAN IsOk = InstructionAnalyze(v1, IsProbe, Is64, &Instruction);
        if (!IsOk)
            return FALSE;

        if (Instruction.Operand1 == 0xFF && Instruction.Operand2 == 0x25
            && *(ULONG*)&v1[2] == 0) {
            // jmp dword/qword ptr [+00], so skip the following ULONG_PTR
            Instruction.Length += sizeof(ULONG_PTR);
        }

        Length2 += Instruction.Length;
        if (Length2 >= Length1)
            break;

        v1 += Instruction.Length;
    }

    *ByteCount = Length2;
    return TRUE;
}


BOOLEAN GetTrampolienCode(
    _TRAMPOLINE_* Trampoline, void* ServiceAddress,
    ULONG ByteCount, BOOLEAN Is64, BOOLEAN IsProbe)
{
    UCHAR* Source = (UCHAR*)ServiceAddress;
    UCHAR* CodeData = Trampoline->CodeData;
    ULONG DataLength;
    BOOLEAN IsPushPopRax = FALSE;

    Trampoline->EyeCatcher = POOL_TAG;
    Trampoline->TargetAddress = Source + ByteCount;
    Trampoline->ByteCount = ByteCount;

    // copy ByteCount bytes from the original source function into
    // the code area of the trampoline stub, adjustmenting it as needed
    // in 32-bit mode, we also relocate call/jump targets. (E8/E9)
    // in 64-bit mode, we also relocate rip-based displacements

    while ((ULONG_PTR)(Source - (UCHAR*)ServiceAddress) < ByteCount) {

        _INSTRUCTION_ Instruction;
        BOOLEAN IsOk = InstructionAnalyze(Source, IsProbe, Is64, &Instruction);
        if (!IsOk)
            return FALSE;

        memcpy(CodeData, Source, Instruction.Length);   //拷贝源函数指令
        DataLength = Instruction.Length;

        if ((Instruction.Operand1 >= 0x70 && Instruction.Operand1 <= 0x7F) ||
            (Instruction.Operand1 == 0x0F && (Instruction.Operand2 >= 0x80 && Instruction.Operand2 <= 0x8F))) {

            // conditional-jmp with 8-bit or 32-bit displacement

            UCHAR v1;
            if (Instruction.Operand1 == 0x0F)
                v1 = Instruction.Operand2 & 0x0F;
            else
                v1 = Instruction.Operand2 & 0x0F;

            if (Is64) {

                // in 64-bit mode, rewrite as indirect jmp/call:
                //           jcc cont (opposite condition)
                //           jmp qword ptr [target64]
                // target64: dq  target
                // (cont):   ...

                CodeData[0] = 0x70 | (v1 ^ 1);    // jcc cont (rip+16)
                CodeData[1] = 14;
                CodeData[2] = 0xFF;                 // jmp [rip+6]
                CodeData[3] = 0x25;
                *(LONG*)&CodeData[4] = 0;
                *(ULONG_PTR*)&CodeData[8] = (ULONG_PTR)Instruction.ParameterData;

                DataLength = 16;

            }
            else {

                // in 32-bit mode, fix jmp target relative to new eip,
                // and write out jcc disp32

                CodeData[0] = 0x0F;                 // jcc disp32
                CodeData[1] = 0x80 | v1;
                *(ULONG*)&CodeData[2] =
                    (ULONG)(Instruction.ParameterData - ((ULONG_PTR)CodeData + 6));

                DataLength = 6;
            }

        }
        else if (Instruction.Operand1 == 0xEB) {

            // unconditional short jump with 8-bit displacement

            if (Is64) {

                // in 64-bit mode, rewrite as indirect jmp/call:
                //           jmp qword ptr [target64]
                // target64: dq  target

                CodeData[0] = 0xFF;                 // jmp [rip+6]
                CodeData[1] = 0x25;
                *(LONG*)&CodeData[2] = 0;
                *(ULONG_PTR*)&CodeData[6] = (ULONG_PTR)Instruction.ParameterData;

                DataLength = 14;

            }
            else {

                // in 32-bit mode, fix jmp target relative to new eip,
                // and write out jcc disp32

                CodeData[0] = 0xE9;                 // jmp disp32
                *(ULONG*)&CodeData[1] =
                    (ULONG)(Instruction.ParameterData - ((ULONG_PTR)CodeData + 5));

                DataLength = 5;
            }

        }
        else if (Instruction.Operand1 == 0xE8 || Instruction.Operand1 == 0xE9) {

            // simple direct jmp/call with 32-bit displacement

            if (Is64) {

                // in 64-bit mode, rewrite as indirect jmp/call:
                //           jmp qword ptr [target64]
                //           jmp cont
                // target64: dq  target
                // cont:     ...

                CodeData[0] = 0xFF;         // jmp/call [rip+8]
                CodeData[1] = (Instruction.Operand1 == 0xE8) ? 0x15 : 0x25;
                *(LONG*)&CodeData[2] = 2;
                CodeData[6] = 0xEB;         // jmp cont (rip+8)
                CodeData[7] = 0x08;
                *(ULONG_PTR*)&CodeData[8] = (ULONG_PTR)Instruction.ParameterData;

                DataLength = 16;

            }
            else {

                // in 32-bit mode, fix jmp target relative to new eip

                ULONG* Rel32 = (ULONG*)(CodeData + ((UCHAR*)Instruction.Rel32 - Source));
                *Rel32 = (ULONG)(Instruction.ParameterData - ((ULONG_PTR)CodeData + Instruction.Length));
            }

        }
        else if (Instruction.Operand1 == 0xFF && Instruction.Operand2 == 0x25 &&
            *(ULONG*)&Source[2] == 0) {

            //
            // indirect jmp to the immediately following address:
            //      jmp dword/qword ptr [+00]
            // typically found when the entry point is already hooked
            // by someone else.  we retrieve the jump target from the
            // instruction and use it for the trampoline jump target,
            // then break
            //

            if (Is64)
                Trampoline->TargetAddress = (void*)(*(ULONG64*)&Source[6]);
            else
                Trampoline->TargetAddress = (void*)(ULONG_PTR)(*(ULONG*)&Source[6]);

            break;

        }
        else if (Is64 && Instruction.ModRM && (Instruction.ModRM[0] & 0xC7) == 5) {

            // RIP-relative addressing in 64-bit mode, when the
            // instruction contains modrm byte: mod==00b, rm==101b.
            // (high two bits are zero, low three bits have a value of 5)

            UCHAR* ModRM;

            // we rewrite the original instruction to use RAX as the
            // base, rather than RIP, and prefix an instruction that
            // loads RAX with the original RIP.

            if (IsPushPopRax) {
                *CodeData = 0x50;           // push rax
                ++CodeData;
            }

            CodeData[0] = 0x48;             // mov rax, addr
            CodeData[1] = 0xB8;
            *(ULONG_PTR*)&CodeData[2] = ((ULONG_PTR)Source) + Instruction.Length;
            CodeData += 10;

            memcpy(CodeData, Source, Instruction.Length);
            ModRM = CodeData + (Instruction.ModRM - Source);
            *ModRM = (*ModRM | 0x80) & (~7);

            if (IsPushPopRax)
            {
                CodeData += Instruction.Length;
                *CodeData = 0x58;           // pop rax
                ++CodeData;
                // we already advanced the code pointer to insert the pop
                // instruction so we don't want to advance it again:
                DataLength = 0;
            }

        }
        else if (Is64 && Instruction.Operand1 == 0x8B && Instruction.Operand2 == 0xC4) {

            // if rax is used in the prolog, we will need to push and
            // pop it before using it in the code generated above for
            // RIP-relative addressing in 64-bit mode

            IsPushPopRax = TRUE;
        }

        Source += Instruction.Length;
        CodeData += DataLength;
    }

    // stub ends with a jump to the original entrypoint.  first qword
    // in the stub contains the address of the original entrypoint

    CodeData[0] = 0xFF;                     // jmp dword/qword ptr [target]
    CodeData[1] = 0x25;
    CodeData += 2;
    if (Is64) {
        *(LONG*)CodeData = (LONG)((UCHAR*)&Trampoline->TargetAddress - (CodeData + 4));
        CodeData += 8;
    }
    else {
        *(ULONG*)CodeData = (ULONG)(ULONG_PTR)&Trampoline->TargetAddress;
        CodeData += 4;
    }

    DataLength = (ULONG)(CodeData - (UCHAR*)Trampoline);
    DataLength = (DataLength + 15) & (~0x0F);   // align to 16-byte boundary
    Trampoline->DataLength = DataLength;   //0x30

    /*
    0:000> u 000007ff`fff80218 l 10
    000007ff`fff80218 4c8bd1          mov     r10,rcx
    000007ff`fff8021b b80d000000      mov     eax,0Dh
    000007ff`fff80220 0f05            syscall
    000007ff`fff80222 c3              ret
    000007ff`fff80223 0f1f440000      nop     dword ptr [rax+rax]
    000007ff`fff80228 ff25e2ffffff    jmp     qword ptr [000007ff`fff80210]   覆盖指令之后的指令


    0:000> dq 000007ff`fff80210
    000007ff`fff80210  00000000`77bf13c0
    

    0:000> u 00000000`77bf13c0
    ntdll!NtQueryInformationFile:
    00000000`77bf13c0 4c8bd1          mov     r10,rcx
    00000000`77bf13c3 b80e000000      mov     eax,0Eh
    00000000`77bf13c8 0f05            syscall
    00000000`77bf13ca c3              ret
    00000000`77bf13cb 0f1f440000      nop     dword ptr [rax+rax]



    ntdll!NtQueryObject:
    00000000`77bf13b0 4c8bd1          mov     r10,rcx
    00000000`77bf13b3 b80d000000      mov     eax,0Dh
    00000000`77bf13b8 0f05            syscall
    00000000`77bf13ba c3              ret
    00000000`77bf13bb 0f1f440000      nop     dword ptr [rax+rax]
    ntdll!NtQueryInformationFile:
    00000000`77bf13c0 4c8bd1          mov     r10,rcx
    00000000`77bf13c3 b80e000000      mov     eax,0Eh
    00000000`77bf13c8 0f05            syscall
    
    */




    return TRUE;
}
