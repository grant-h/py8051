#ifndef I8051_DISASM_H
#define I8051_DISASM_H

typedef unsigned char UChar;
typedef char Char;
typedef unsigned short UShort;
typedef short Short;
typedef unsigned int UInt;
typedef int Int;
typedef unsigned long ULong;
typedef long Long;

enum InstructionOperation {
   INVALID = 0, ACALL, ADD, ADDC, AJMP, ANL, CJNE, CLR, CPL, DA, DEC, DIV,
   DJNZ, INC, JB, JBC, JC, JMP, JNB, JNC, JNZ, JZ, LCALL, LJMP, MOV, MOVC,
   MOVX, MUL, NOP, ORL, POP, PUSH, RET, RETI, RL, RLC, RR, RRC, SETB, SJMP,
   SUBB, SWAP, XCH, XCHD, XRL
};

enum OperandType {
   NOOP = 0,
   OP_A, OP_B, OP_REG, OP_DPTR, OP_IDPTR, /* A, B, R0-R7, DPTR, @DPTR registers */
   OP_C, /* C flag */
   OP_DIRECT, OP_OFF, /* Direct addressing and signed offset (8-bit) */
   OP_ID_REG, /* Indirect @R0, @R1 */
   OP_I8, OP_I16, /* Immediate 8-bits, 16-bits */
   OP_BIT, /* For accessing special bit addresses */
   OP_ADDR11, OP_ADDR16, /* Address 11-bits, 16-bits */
   OP_IDRA_DPTR, OP_IDRA_PC /* Special relative calculations: @A+DPTR, @A+PC */
};

// DO NOT CHANGE: structure required for the disasm table
struct InstructionOperands {
   enum OperandType op1;
   enum OperandType op2;
   enum OperandType op3;
};

// DO NOT CHANGE: structure required for the disasm table
struct InstructionEncoding {
   enum InstructionOperation opcode;
   struct InstructionOperands operands;
};

struct OperandResult {
   enum OperandType type;
   UChar size; /* size of operand in bytes */

   union {
      UChar u8;
      Char s8;
      UShort u16;
      Short s16;
   } data;
};

struct Instruction {
   struct InstructionEncoding * encoding;
   UChar size;
   UChar numOperands; /* number of non NOOP operands */

   struct {
      struct OperandResult op[3];
   } data;
};

Long i8051DecodeInsn(struct Instruction * insn, const UChar * guest_code, Long delta);

const char * i8051ToStr(enum InstructionOperation op);
void i8051Print(struct Instruction * insn, UChar * string, UInt size);

#endif
