#pragma once
#include "Common.h"




#define _F_DATA_SIZE(f)     (((f) & 0xFF))
#define _F_ADDR_SIZE(f)     (((f) & 0xFFFF) >> 8)
#define _F_REX(f)           (((f) & 0xFFFFFF) >> 16)
#define F_DATA_SIZE()       (_F_DATA_SIZE(Instruction->Flags))
#define F_ADDR_SIZE()       (_F_ADDR_SIZE(Instruction->Flags))
#define F_REX()             (_F_REX(Instruction->Flags))
#define F_64_BIT            (0xF0 << 16)

#define F_MAKE_COMBO(dataSize, addrSize, rex)   \
    (                                           \
        (((dataSize) & 0xFF)) |                 \
        (((addrSize) & 0xFF) << 8) |            \
        (((rex) & 0xFF) << 16)                  \
    )

#define F_REG(f)            ((f & 0x38) >> 3)



enum _KIND_ {

    INST_UNKNOWN = 0,
    INST_MOVE,
    INST_CTLXFER,           // jmp/jcc/call with 32-bit disp
    INST_CTLXFER_REG,       // jmp/call reg or [reg]
    INST_CALL_MEM,          // call [mem]
    INST_JUMP_MEM,          // jmp  [mem]
    INST_SYSCALL,
    INST_RET
};

#pragma pack(1)
typedef struct _INSTRUCTION_ {

    ULONG Length;
    UCHAR Kind;
    UCHAR Operand1, Operand2;
    ULONG64 ParameterData;
    LONG* Rel32;            // --> 32-bit relocation for control-xfer
    UCHAR* ModRM;
    ULONG Flags;

}INSTRUCTION;


BOOLEAN InstructionAnalyze(
    void* ServiceAddress,
    BOOLEAN probe_address,
    BOOLEAN Is64,
    INSTRUCTION* Instruction);

UCHAR* InstructionAnalyzePrefix(UCHAR* ServiceAddress, BOOLEAN Is64, ULONG* Flags);
UCHAR* InstructionAnalyzeInternal(UCHAR* ServiceAddress, INSTRUCTION* Instruction);
UCHAR* AnalyzeModRM(UCHAR* ModRM, INSTRUCTION* Instruction);
UCHAR* AnalyzeCtlXfer(UCHAR* ServiceAddress, INSTRUCTION* Instruction);