#include "InstructionAnalyze.h"

static const UCHAR _Opcodes_1[256] = {

    /*   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F */
    /* 0 */  1, 1, 1, 1, 2, 3, 6, 6, 1, 1, 1, 1, 2, 3, 6, 0,
    /* 1 */  1, 1, 1, 1, 2, 3, 6, 6, 1, 1, 1, 1, 2, 3, 6, 6,
    /* 2 */  1, 1, 1, 1, 2, 3, 0, 6, 1, 1, 1, 1, 2, 3, 0, 6,
    /* 3 */  1, 1, 1, 1, 2, 3, 0, 6, 1, 1, 1, 1, 2, 3, 0, 6,
    /* 4 */  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    /* 5 */  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    /* 6 */  6, 6, 1, 1, 1, 0, 0, 0, 3, 0, 2, 0, 6, 6, 6, 6,
    /* 7 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 8 */  4, 5, 4, 4, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 2, 1,
    /* 9 */  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 0, 6, 6, 6, 6, 6,
    /* A */  7, 7, 7, 7, 6, 6, 6, 6, 2, 3, 6, 6, 6, 6, 6, 6,
    /* B */  2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
    /* C */  4, 4, 3, 6, 0, 0, 4, 5, 0, 6, 3, 6, 6, 2, 6, 6,
    /* D */  1, 1, 1, 1, 2, 2, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0,
    /* E */  2, 2, 2, 2, 2, 2, 2, 2, 3, 0, 0, 0, 6, 6, 6, 6,
    /* F */  0, 0, 0, 0, 6, 6, 0, 0, 6, 6, 6, 6, 6, 6, 0, 0
};



BOOLEAN InstructionAnalyze(
    void* ServiceAddress,
    BOOLEAN probe_address,
    BOOLEAN Is64,
    INSTRUCTION* Instruction)
{
    UCHAR* v1;
    WCHAR text[64];

    ZeroMemory(Instruction, sizeof(INSTRUCTION));

    __try {

#ifdef KERNEL_MODE
        if (probe_address)
            ProbeForRead(address, 16, sizeof(UCHAR));
#endif

        /*if (1) {
            UCHAR *z = (UCHAR *)address;
            DbgPrint("%p - %02X %02X %02X %02X %02X %02X %02X %02X\n", z, z[0], z[1], z[2], z[3], z[4], z[5], z[6], z[7]);
            z += 8;
            DbgPrint("%p - %02X %02X %02X %02X %02X %02X %02X %02X\n", z, z[0], z[1], z[2], z[3], z[4], z[5], z[6], z[7]);
        }*/
        // DbgPrint("*** Analyzing pfx  at %08X\n", address);
        v1 = InstructionAnalyzePrefix((UCHAR*)ServiceAddress, Is64, &Instruction->Flags);
        Instruction->Operand1 = v1[0];
        Instruction->Operand2 = v1[1];
        // DbgPrint("    Analyzing inst at %08X\n", addr);
        v1 = InstructionAnalyzeInternal(v1, Instruction);
        if (!v1) {
            v1 = (UCHAR*)ServiceAddress;
#ifdef KERNEL_MODE
         
#else
          
#endif
            
            v1 = NULL;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {

        v1 = NULL;
#ifdef KERNEL_MODE

#else

#endif

    }
    if (!v1)
        return FALSE;

    Instruction->Length = (ULONG)(v1 - (UCHAR*)ServiceAddress);
    return TRUE;
}
UCHAR* InstructionAnalyzePrefix(UCHAR* ServiceAddress, BOOLEAN Is64, ULONG* Flags)
{
    ULONG rex, Size1, Size2;
    UCHAR v1;

    rex = 0;
    Size1 = 4;
    Size2 = Is64 ? 8 : 4;

    while (1) {

        v1 = *ServiceAddress;
        ++ServiceAddress;

        if (v1 == 0x2E ||                // CS: override prefix 2E
            v1 == 0x3E ||                // DS: override prefix 3E
            v1 == 0x26 ||                // ES: override prefix 26
            v1 == 0x64 ||                // FS: override prefix 64
            v1 == 0x65 ||                // GS: override prefix 65
            v1 == 0x36 ||                // SS: override prefix 36
            v1 == 0xF0 ||                // LOCK prefix
            v1 == 0xF3 ||                // REP or REPZ prefix
            v1 == 0xF2)                  // REPNZ prefix
            continue;

        if (v1 == 0x66) {                // Operand-size override prefix 66
            Size1 = 2;
            continue;
        }

        if (v1 == 0x67) {                // Address-size override prefix 67
            Size2 = Is64 ? 4 : 2;
            continue;
        }

        if (Is64 && (v1 & 0xF0) == 0x40) {   // REX prefix 4x
            rex = v1 & 0x0F;
            continue;
        }

        --ServiceAddress;                         // Not a prefix byte
        break;
    }

    if (Is64 && (rex & 8))              // REX.W prefix
        Size1 = 8;

    // in 64-bit mode, 64-bits of addr or data are usually sign-extended
    // from only 32-bits encoded in the instruction.  only in two cases
    // an instruction actually encodes full 64-bits of information:
    //
    // - moving to/from accum register:                 opcodes A0..A3
    //   - this is the default, unless overridden
    //     by prefix 67
    //
    // - moving immediate value to any register:        opcodes B8..BF
    //   - prefix 48, REX.W, must be specified for this

    if (Size2 == 8 && (v1 < 0xA0 || v1 > 0xA3))
        Size2 = 4;
    if (Size1 == 8 && (v1 < 0xB8 || v1 > 0xBF))
        Size1 = 4;

    // encode prefix information into the flags

    *Flags = F_MAKE_COMBO(Size1, Size2, rex);
    if (Is64)
        *Flags |= F_64_BIT;

    return ServiceAddress;
}


UCHAR* InstructionAnalyzeInternal(UCHAR* ServiceAddress, INSTRUCTION* Instruction)
{
    UCHAR* v1;
    UCHAR Operand1, Operand2;

    v1 = AnalyzeCtlXfer(ServiceAddress, Instruction);
    if (v1 != ServiceAddress)
        return v1;

    Operand1 = ServiceAddress[0];
    Operand2 = ServiceAddress[1];

    switch (_Opcodes_1[Operand1]) {

    case 1:
        return AnalyzeModRM(ServiceAddress + 1, Instruction);

    case 2:
        return ServiceAddress + 2;

    case 3:
        if (F_DATA_SIZE() == 8) 
        {
            Instruction->ParameterData = *(ULONG64*)(ServiceAddress + 1);
            return ServiceAddress + 1 + 8;
        }
        if (F_DATA_SIZE() == 4) {
            Instruction->ParameterData = (ULONG64) * (ULONG*)(ServiceAddress + 1);
            return ServiceAddress + 1 + 4;
        }
        if (F_DATA_SIZE() == 2) {
            Instruction->ParameterData = (ULONG64) * (USHORT*)(ServiceAddress + 1);
            return ServiceAddress + 1 + 2;
        }
        break;

    case 4:
        return AnalyzeModRM(ServiceAddress + 1, Instruction) + 1;

    case 5:
        return AnalyzeModRM(ServiceAddress + 1, Instruction) + F_DATA_SIZE();

    case 6:
        return ServiceAddress + 1;

    case 7:
        return ServiceAddress + 1 + F_ADDR_SIZE();
    }

    // special opcodes

    if (Operand1 == 0xF6 || Operand1 == 0xF7) {
        if (F_REG(Operand2) == 0) {          // F6/F7 test opcode
            if (Operand1 == 0xF6)             // 8-bit
                return AnalyzeModRM(ServiceAddress + 1, Instruction) + 1;
            else                        // 16/32-bit
                return AnalyzeModRM(ServiceAddress + 1, Instruction) + F_DATA_SIZE();
        }
        else {
            // div, idiv, mul, imul, neg, not
            return AnalyzeModRM(ServiceAddress + 1, Instruction);
        }
    }

    // double-byte opcodes escaped by FE

    if (Operand1 == 0xFE) {

        if (F_REG(Operand2) == 0 || F_REG(Operand2) == 1)         // inc/dec
            return AnalyzeModRM(ServiceAddress + 1, Instruction);

    }

    // double-byte opcodes escaped by FF

    if (Operand1 == 0xFF) {

        if (F_REG(Operand2) == 0 || F_REG(Operand2) == 1 ||       // inc/dec
            F_REG(Operand2) == 6)                            // push
            return AnalyzeModRM(ServiceAddress + 1, Instruction);

    }

    // double-byte opcodes escaped by 0F

    if (Operand1 == 0x0F) {

        if ((Operand2 >= 0x19 && Operand2 <= 0x1F) ||     // nop r/m
            (Operand2 >= 0x40 && Operand2 <= 0x4F) ||     // cmovxx r/m
            (Operand2 >= 0x90 && Operand2 <= 0x9F))       // setxx r/m
            return AnalyzeModRM(ServiceAddress + 2, Instruction);

        switch (Operand2) {

        case 0x10:                  // movups xmm?
            return ServiceAddress + 4;
        case 0x57:                  // xorps
            return ServiceAddress + 3;
        case 0xA0:                  // push fs
        case 0xA8:                  // push gs
            return ServiceAddress + 2;

        case 0xA5:                  // shld r/m
        case 0xAD:                  // shrd r/m
        case 0xAF:                  // imul r/m
        case 0xB6:                  // movzx r/m
        case 0xB7:                  // movzx r/m
        case 0xBE:                  // movsx r/m
        case 0xBF:                  // movsx r/m
        case 0xA3:                  // bt   r/m
        case 0xAB:                  // bts  r/m
        case 0xB3:                  // btr  r/m
        case 0xBB:                  // btc  r/m
            return AnalyzeModRM(ServiceAddress + 2, Instruction);

        case 0xBA:                  // bt, bts, btr, btc imm8
        case 0xA4:                  // shld r/m, imm8
        case 0xAC:                  // shrd r/m, imm8
            return AnalyzeModRM(ServiceAddress + 2, Instruction) + 1;
        }

        // special instruction

        // DbgPrint("Inst = %02X/%02X\n", op, Operand2);

        if (Operand2 == 0x00 || Operand2 == 0x01) {       // 0F 00/01

            UCHAR Operand3 = ServiceAddress[2];
            Operand3 = ((Operand2 & 1) << 7) | F_REG(Operand3);

            //DbgPrint("Addr[] = %02X/%02X --> %02X\n", Operand2, addr[2], op3);

            if (Operand3 == 0x00 ||                          // sldt r/m
                Operand3 == 0x01 ||                          // str r/m
                Operand3 == 0x80 ||                          // sgdt mem
                Operand3 == 0x81) {                          // sidt mem

                return AnalyzeModRM(ServiceAddress + 2, Instruction);
            }
        }

    }

    // unhandled opcode

    return NULL;
}



UCHAR* AnalyzeModRM(UCHAR* ModRM, INSTRUCTION* Instruction)
{
    UCHAR v1;

    // if opcode implies a modrm field, we need to skip one or
    // two bytes of modrm field, and possibly additional one
    // or four bytes of displacement

    Instruction->ModRM = ModRM;
    v1 = 0xFF;                // indicate no displacement

    // mod == 11b:  one-byte modrm, no displacements
    if ((ModRM[0] & 0xC0) == 0xC0)
        ++ModRM;                // skip one byte of modrm

    // (mod != 11b) && (rm == 100b) && (! 16-bit):  two-byte modrm.
    // displacement is governed by mod and base fields,
    // where base is low 3 bits of second modrm byte (aka SIB).
    // interpretation of mod+base is same as that of
    // mod+rm for purposes of deciding size of displacement
    else if ((F_ADDR_SIZE() != 2) && (ModRM[0] & 7) == 4) {
        v1 = (ModRM[0] & 0xC0) | (ModRM[1] & 7);
        ModRM += 2;             // skip two bytes of modrm

    // (mod != 11b) && (rm != 100b):  one-byte modrm.
    // displacement is governed by mod+rm fields, see
    // interpretation below
    }
    else {
        v1 = (ModRM[0] & 0xC0) | (ModRM[0] & 7);
        ++ModRM;                // skip one byte of modrm
    }

    // displacement is one byte if mod == 01b,
    // four bytes if mod == 10b (option 1), or
    // four bytes if mod == 00b and rm/base == 101b (option 2)
    if (v1 != 0xFF) {
        if ((v1 & 0xC0) == 0x40)
            ++ModRM;            // skip 8-bit displacement
        else if ((v1 & 0xC0) == 0x80 ||
            (v1 & 7) == 5)
            ModRM += 4;         // skip 32-bit displacement
    }

    return ModRM;
}


UCHAR* AnalyzeCtlXfer(UCHAR* ServiceAddress, INSTRUCTION* Instruction)
{
    UCHAR Operand1, Operand2;
    LONG Rel32;
    BOOLEAN IsRel32;

    Operand1 = ServiceAddress[0];
    Operand2 = ServiceAddress[1];
    Rel32 = 0;
    IsRel32 = FALSE;

    // system control transfers

    if ((Operand1 == 0x0F && Operand2 == 0x05) ||                 // syscall
        (Operand1 == 0x0F && Operand2 == 0x34) ||                 // sysenter
        (Operand1 == 0xCD && Operand2 == 0x2E)) {                 // int 2e

        Instruction->Kind = INST_SYSCALL;
        ServiceAddress += 2;
    }

    if (Operand1 == 0xCC) {
        Instruction->Kind = INST_RET;
        ++ServiceAddress;
    }

    // return control transfer

    if (Operand1 == 0xC3 || Operand1 == 0xCB ||                   // ret, retf
        Operand1 == 0xC2 || Operand1 == 0xCA) {                   // ret, retf nnn

        Instruction->Kind = INST_RET;
        if (Operand1 & 1)
            ++ServiceAddress;
        else
            ServiceAddress += 3;
    }

    // short jumps with an 8-bit displacement

    if ((Operand1 >= 0x70 && Operand1 <= 0x7F) ||                 // jcc disp8
        (Operand1 >= 0xE0 && Operand1 <= 0xE3) ||                 // loop/jcxz disp8
        (Operand1 == 0xEB)) {                                // jmp disp8

        IsRel32 = TRUE;
        Rel32 = (LONG) * (CHAR*)(ServiceAddress + 1);
        ServiceAddress += 2;
    }

    // control transfer to a near 32-bit displacement

    if (Operand1 == 0x0F && (Operand2 & 0xF0) == 0x80) {          // jcc disp32

        IsRel32 = TRUE;
        Rel32 = *(LONG*)(ServiceAddress + 2);
        ServiceAddress += 6;
    }

    if (Operand1 == 0xE8 || Operand1 == 0xE9) {                   // jmp/call disp32
        IsRel32 = TRUE;
        Instruction->Rel32 = (LONG*)(ServiceAddress + 1);
        Rel32 = *Instruction->Rel32;
        ServiceAddress += 5;
    }

    // double-byte instructions

    if (Operand1 == 0xFF) {

        // control transfer using a register, no displacement

        if ((Operand2 >= 0xD0 && Operand2 <= 0xD7) ||             // call reg
            (Operand2 >= 0xE0 && Operand2 <= 0xE7)) {             // jmp reg

            Instruction->Kind = INST_CTLXFER_REG;
            Instruction->ParameterData = Operand2 & 0x0F;
            ServiceAddress += 2;

        }
        else if (Operand2 == 0x12) {

            // control transfer to [edx]

            Instruction->Kind = INST_CTLXFER_REG;
            Instruction->ParameterData = 0x80 | (Operand2 & 0x0F);
            ServiceAddress += 2;

        }
        else {

            // control transfer using a modrm field

            if ((Operand2 & 0x38) == 0x10 ||                     // call
                (Operand2 & 0x38) == 0x18 ||                     // call
                (Operand2 & 0x38) == 0x20 ||                     // jmp
                (Operand2 & 0x38) == 0x28) {                     // jmp

                Instruction->Kind = (Operand2 >= 0x20) ? INST_JUMP_MEM : INST_CALL_MEM;
                ServiceAddress = AnalyzeModRM(ServiceAddress + 1, Instruction);
            }
        }

    }

    // far jump through call gate to absolute address

    if (Operand1 == 0xEA) {

        USHORT seg = *(USHORT*)(ServiceAddress + 5);
        if (seg == 0x001B || seg == 0x0023) {   // application CS == 0x001B
            Instruction->Kind = INST_CTLXFER;          // on 64-bit, also 0023 ?
            Instruction->ParameterData = *(ULONG*)(ServiceAddress + 1);
            ServiceAddress += 7;
        }
    }

    // fix relative target address

    if (IsRel32) {
        Instruction->Kind = INST_CTLXFER;
        Instruction->ParameterData = (ULONG_PTR)ServiceAddress + Rel32;
    }

    return ServiceAddress;
}