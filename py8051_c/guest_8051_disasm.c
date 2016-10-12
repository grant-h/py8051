
/*--------------------------------------------------------------------*/
/*--- begin                                    guest_8051_disasm.c ---*/
/*--------------------------------------------------------------------*/

/*
   this file is part of valgrind, a dynamic binary instrumentation
   framework.

   copyright (c) 2016 grant hernandez
      grant.hernandez@ufl.edu

   this program is free software; you can redistribute it and/or
   modify it under the terms of the gnu general public license as
   published by the free software foundation; either version 2 of the
   license, or (at your option) any later version.

   this program is distributed in the hope that it will be useful, but
   without any warranty; without even the implied warranty of
   merchantability or fitness for a particular purpose.  see the gnu
   general public license for more details.

   you should have received a copy of the gnu general public license
   along with this program; if not, write to the free software
   foundation, inc., 59 temple place, suite 330, boston, ma
   02111-1307, usa.

   the gnu general public license is contained in the file copying.
*/

/* Disassembles 8051. */

#include <stdio.h>
#include <assert.h>

#include "guest_8051_disasm.h"

#define ENC_ACC                       {OP_A, NOOP, NOOP}           // INSN A
#define ENC_ACC_B                     {OP_A, OP_B, NOOP}           // INSN AB
#define ENC_ACC_DIRECT                {OP_A, OP_DIRECT, NOOP}      // INSN A, (addr)
#define ENC_ACC_DIRECT_OFFSET         {OP_A, OP_DIRECT, OP_OFF}    // INSN A, (addr), offset
#define ENC_INDIRECT_ACC_DPTR_REL     {OP_IDRA_DPTR, NOOP, NOOP}   // INSN @A + DPTR
#define ENC_INDIRECT_DPTR_ACC         {OP_IDPTR, OP_A, NOOP}       // INSN @DPTR, A
#define ENC_ACC_IMM8                  {OP_A, OP_I8, NOOP}          // INSN A, #data
#define ENC_ACC_IMM8_OFFSET           {OP_A, OP_I8, OP_OFF}        // INSN A, #data, offset
#define ENC_ACC_INDIRECT_ACC_DPTR_REL {OP_A, OP_IDRA_DPTR, NOOP}   // INSN A, @A + DPTR
#define ENC_ACC_INDIRECT_ACC_PC_REL   {OP_A, OP_IDRA_PC, NOOP}     // INSN A, @A + PC
#define ENC_ACC_INDIRECT_DPTR         {OP_A, OP_IDPTR, NOOP}       // INSN A, @DPTR
#define ENC_ACC_INDIRECT_R0           {OP_A, OP_ID_REG, NOOP}      // INSN A, @R0
#define ENC_ACC_INDIRECT_R1           {OP_A, OP_ID_REG, NOOP}      // INSN A, @R1
#define ENC_ACC_REG                   {OP_A, OP_REG, NOOP}         // INSN A, Rn
#define ENC_ADDR11                    {OP_ADDR11, NOOP, NOOP}      // INSN{A11-A8} {A7-A0}
#define ENC_ADDR16                    {OP_ADDR16, NOOP, NOOP}      // INSN {A15-A0}
#define ENC_BIT                       {OP_BIT, NOOP, NOOP}         // INSN bit
#define ENC_BIT_CFLAG                 {OP_BIT, OP_C, NOOP}         // INSN bit, C
#define ENC_BIT_OFFSET                {OP_BIT, OP_OFF, NOOP}       // INSN bit, offset
#define ENC_CFLAG                     {OP_C, NOOP, NOOP}           // INSN C, @R0
#define ENC_CFLAG_BIT                 {OP_C, OP_BIT, NOOP}         // INSN C, bit
#define ENC_CFLAG_NBIT                {OP_C, OP_NBIT, NOOP}        // INSN C, /bit
#define ENC_DIRECT                    {OP_DIRECT, NOOP, NOOP}      // INSN (direct)
#define ENC_DIRECT_ACC                {OP_DIRECT, OP_A, NOOP}      // INSN (direct), A
#define ENC_DIRECT_DIRECT             {OP_DIRECT, OP_DIRECT, NOOP} // INSN (direct), (direct)
#define ENC_DIRECT_IMM8               {OP_DIRECT, OP_I8, NOOP}     // INSN (direct), #data
#define ENC_DIRECT_INDIRECT_R0        {OP_DIRECT, OP_ID_REG, NOOP} // INSN (direct), @R0
#define ENC_DIRECT_INDIRECT_R1        {OP_DIRECT, OP_ID_REG, NOOP} // INSN (direct), @R1
#define ENC_DIRECT_OFFSET             {OP_DIRECT, OP_OFF, NOOP}    // INSN (direct), offset
#define ENC_DIRECT_REG                {OP_DIRECT, OP_REG, NOOP}    // INSN (direct), Rn
#define ENC_DPTR                      {OP_DPTR, NOOP, NOOP}        // INSN DPTR
#define ENC_DPTR_ACC                  {OP_DPTR, OP_A, NOOP}        // INSN DPTR, A
#define ENC_DPTR_IMM16                {OP_DPTR, OP_I16, NOOP}      // INSN DPTR, #data16
#define ENC_INDIRECT_R0               {OP_ID_REG, NOOP, NOOP}      // INSN @R0
#define ENC_INDIRECT_R0_ACC           {OP_ID_REG, OP_A, NOOP}      // INSN @R0, A
#define ENC_INDIRECT_R0_DIRECT        {OP_ID_REG, OP_DIRECT, NOOP} // INSN @R0, (direct)
#define ENC_INDIRECT_R0_IMM8          {OP_ID_REG, OP_I8, NOOP}     // INSN @R0, #data
#define ENC_INDIRECT_R0_IMM8_OFFSET   {OP_ID_REG, OP_I8, OP_OFF}   // INSN @R0, #data, offset
#define ENC_INDIRECT_R1               {OP_ID_REG, NOOP, NOOP}      // INSN @R1
#define ENC_INDIRECT_R1_ACC           {OP_ID_REG, OP_A, NOOP}      // INSN @R1, A
#define ENC_INDIRECT_R1_DIRECT        {OP_ID_REG, OP_DIRECT, NOOP} // INSN @R1, (direct)
#define ENC_INDIRECT_R1_IMM8          {OP_ID_REG, OP_I8, NOOP}     // INSN @R1, #data
#define ENC_INDIRECT_R1_IMM8_OFFSET   {OP_ID_REG, OP_I8, OP_OFF}   // INSN @R1, #data, offset
#define ENC_NO_OPERAND                {NOOP, NOOP, NOOP}           // INSN
#define ENC_OFFSET                    {OP_OFF, NOOP, NOOP}         // INSN offset
#define ENC_REG                       {OP_REG, NOOP, NOOP}         // INSN Rn
#define ENC_REG_ACC                   {OP_REG, OP_A, NOOP}         // INSN Rn, A
#define ENC_REG_DIRECT                {OP_REG, OP_DIRECT, NOOP}    // INSN Rn, (direct)
#define ENC_REG_IMM8                  {OP_REG, OP_I8, NOOP}        // INSN Rn, #data
#define ENC_REG_IMM8_OFFSET           {OP_REG, OP_I8, OP_OFF}      // INSN Rn, #data, offset
#define ENC_REG_OFFSET                {OP_REG, OP_OFF, NOOP}       // INSN Rn, offset

// Opcode map helpers
#define REPEAT_R0_TO_R7(op, encoding) \
   {op, encoding}, {op, encoding}, {op, encoding}, {op, encoding}, \
   {op, encoding}, {op, encoding}, {op, encoding}, {op, encoding}

#define OP_PATTERN_0(op) \
   {op, ENC_ACC}, {op, ENC_DIRECT}, {op, ENC_INDIRECT_R0}, {op, ENC_INDIRECT_R1}
#define OP_PATTERN_1(op) \
   {op, ENC_ACC_IMM8}, {op, ENC_ACC_DIRECT}, {op, ENC_ACC_INDIRECT_R0}, {op, ENC_ACC_INDIRECT_R1}

// Built from this table http://www.atmel.com/images/doc0509.pdf
// and http://www.keil.com/support/man/docs/is51/is51_opcodes.htm
// Inspired by https://github.com/Vector35/asmx86
static const struct InstructionEncoding opcodeMap[256] = {
   {NOP, ENC_NO_OPERAND}, {AJMP, ENC_ADDR11}, {LJMP, ENC_ADDR16}, {RR, ENC_ACC}, // 0x00 - 0x03
   OP_PATTERN_0(INC), // 0x04 - 0x07
   REPEAT_R0_TO_R7(INC, ENC_REG), // 0x08 - 0x0f

   {JBC, ENC_BIT_OFFSET}, {ACALL, ENC_ADDR11}, {LCALL, ENC_ADDR16}, {RRC, ENC_ACC}, // 0x10 - 0x13
   OP_PATTERN_0(DEC), // 0x14 - 0x17
   REPEAT_R0_TO_R7(DEC, ENC_REG), // 0x18 - 0x1f

   {JB, ENC_BIT_OFFSET}, {AJMP, ENC_ADDR11}, {RET, ENC_NO_OPERAND}, {RL, ENC_ACC}, // 0x20 - 0x23
   OP_PATTERN_1(ADD), // 0x24 - 0x27
   REPEAT_R0_TO_R7(ADD, ENC_ACC_REG), // 0x28 - 0x2f

   {JNB, ENC_BIT_OFFSET}, {ACALL, ENC_ADDR11}, {RETI, ENC_NO_OPERAND}, {RLC, ENC_ACC}, // 0x30 - 0x33
   OP_PATTERN_1(ADDC), // 0x34 - 0x37
   REPEAT_R0_TO_R7(ADDC, ENC_ACC_REG), // 0x38 - 0x3f

   {JC, ENC_OFFSET}, {AJMP, ENC_ADDR11}, {ORL, ENC_DIRECT_ACC}, {ORL, ENC_DIRECT_IMM8}, // 0x40 - 0x43
   OP_PATTERN_1(ORL), // 0x44 - 0x47
   REPEAT_R0_TO_R7(ORL, ENC_ACC_REG), // 0x48 - 0x4f

   {JNC, ENC_OFFSET}, {ACALL, ENC_ADDR11}, {ANL, ENC_DIRECT_ACC}, {ANL, ENC_DIRECT_IMM8}, // 0x50 - 0x53
   OP_PATTERN_1(ANL), // 0x54 - 0x57
   REPEAT_R0_TO_R7(ANL, ENC_ACC_REG), // 0x58 - 0x5f

   {JZ, ENC_OFFSET}, {AJMP, ENC_ADDR11}, {XRL, ENC_DIRECT_ACC}, {XRL, ENC_DIRECT_IMM8}, // 0x60 - 0x63
   OP_PATTERN_1(XRL), // 0x64 - 0x67
   REPEAT_R0_TO_R7(XRL, ENC_ACC_REG), // 0x68 - 0x6f

   {JNZ, ENC_OFFSET}, {ACALL, ENC_ADDR11}, {ORL, ENC_CFLAG_BIT}, {JMP, ENC_INDIRECT_ACC_DPTR_REL}, // 0x70 - 0x73
   {MOV, ENC_ACC_IMM8}, {MOV, ENC_DIRECT_IMM8}, {MOV, ENC_INDIRECT_R0_IMM8}, {MOV, ENC_INDIRECT_R1_IMM8}, // 0x74 - 0x77
   REPEAT_R0_TO_R7(MOV, ENC_REG_IMM8), // 0x78 - 0x7f

   // 0x80 - 0xff

   {SJMP, ENC_OFFSET}, {AJMP, ENC_ADDR11}, {ANL, ENC_CFLAG_BIT}, {MOVC, ENC_ACC_INDIRECT_ACC_PC_REL}, // 0x80 - 0x83
   {DIV, ENC_ACC_B}, {MOV, ENC_DIRECT_DIRECT}, {MOV, ENC_DIRECT_INDIRECT_R0}, {MOV, ENC_DIRECT_INDIRECT_R1}, // 0x84 - 0x87
   REPEAT_R0_TO_R7(MOV, ENC_DIRECT_REG), // 0x88 - 0x8f

   {MOV, ENC_DPTR_IMM16}, {ACALL, ENC_ADDR11}, {MOV, ENC_BIT_CFLAG}, {MOVC, ENC_ACC_INDIRECT_ACC_DPTR_REL}, // 0x90 - 0x93
   {SUBB, ENC_ACC_IMM8}, {SUBB, ENC_ACC_DIRECT}, {SUBB, ENC_ACC_INDIRECT_R0}, {SUBB, ENC_ACC_INDIRECT_R1}, // 0x94 - 0x97
   REPEAT_R0_TO_R7(SUBB, ENC_ACC_REG), // 0x98 - 0x9f

   {ORL, ENC_CFLAG_NBIT}, {AJMP, ENC_ADDR11}, {MOV, ENC_CFLAG_BIT}, {INC, ENC_DPTR}, // 0xa0 - 0xa3
   {MUL, ENC_ACC_B}, {INVALID, ENC_NO_OPERAND}, {MOV, ENC_INDIRECT_R0_DIRECT}, {MOV, ENC_INDIRECT_R1_DIRECT}, // 0xa4 - 0xa7
   REPEAT_R0_TO_R7(MOV, ENC_REG_DIRECT), // 0xa8 - 0xaf

   {ANL, ENC_CFLAG_NBIT}, {ACALL, ENC_ADDR11}, {CPL, ENC_BIT}, {CPL, ENC_CFLAG}, // 0xb0 - 0xb3
   {CJNE, ENC_ACC_IMM8_OFFSET}, {CJNE, ENC_ACC_DIRECT_OFFSET}, {CJNE, ENC_INDIRECT_R0_IMM8_OFFSET}, {CJNE, ENC_INDIRECT_R1_IMM8_OFFSET}, // 0xb4 - 0xb7
   REPEAT_R0_TO_R7(CJNE, ENC_REG_IMM8_OFFSET), // 0xb8 - 0xbf

   {PUSH, ENC_DIRECT}, {AJMP, ENC_ADDR11}, {CLR, ENC_BIT}, {CLR, ENC_CFLAG}, // 0xc0 - 0xc3
   {SWAP, ENC_ACC}, {XCH, ENC_ACC_DIRECT}, {XCH, ENC_ACC_INDIRECT_R0}, {XCH, ENC_ACC_INDIRECT_R1}, // 0xc4 - 0xc7
   REPEAT_R0_TO_R7(XCH, ENC_DIRECT_REG), // 0xc8 - 0xcf

   {POP, ENC_DIRECT}, {ACALL, ENC_ADDR11}, {SETB, ENC_BIT}, {SETB, ENC_CFLAG}, // 0xd0 - 0xd3
   {DA, ENC_ACC}, {DJNZ, ENC_DIRECT_OFFSET}, {XCHD, ENC_ACC_INDIRECT_R0}, {XCHD, ENC_ACC_INDIRECT_R1}, // 0xd4 - 0xd7
   REPEAT_R0_TO_R7(DJNZ, ENC_REG_OFFSET), // 0xd8 - 0xdf

   {MOVX, ENC_ACC_INDIRECT_DPTR}, {AJMP, ENC_ADDR11}, {MOVX, ENC_ACC_INDIRECT_R0}, {MOVX, ENC_ACC_INDIRECT_R1}, // 0xe0 - 0xe3
   {CLR, ENC_ACC}, {MOV, ENC_ACC_DIRECT}, {MOV, ENC_ACC_INDIRECT_R0}, {MOV, ENC_ACC_INDIRECT_R1}, // 0xe4 - 0xe7
   REPEAT_R0_TO_R7(MOV, ENC_ACC_REG), // 0xe8 - 0xef

   {MOVX, ENC_INDIRECT_DPTR_ACC}, {ACALL, ENC_ADDR11}, {MOVX, ENC_INDIRECT_R0_ACC}, {MOVX, ENC_INDIRECT_R1_ACC}, // 0xf0 - 0xf3
   {CPL, ENC_ACC}, {MOV, ENC_DIRECT_ACC}, {MOV, ENC_INDIRECT_R0_ACC}, {MOV, ENC_INDIRECT_R1_ACC}, // 0xf4 - 0xf7
   REPEAT_R0_TO_R7(MOV, ENC_REG_ACC) // 0xf8 - 0xff
};

/*------------------------------------------------------------*/
/*--- Functions                                            ---*/
/*------------------------------------------------------------*/

static Long loadOperands(struct Instruction * insn, const UChar * guest_code, Long delta);

Long i8051DecodeInsn(struct Instruction * insn, const UChar * guest_code, Long delta)
{
   if(!insn || !guest_code)
      return delta;

   UChar opcode = guest_code[delta];

   // Look up the instruction type and operand types
   insn->encoding = &opcodeMap[opcode];
   insn->numOperands = 0;
   insn->size = 0;

   // Load any operand data and fill in instruction data fields
   return loadOperands(insn, guest_code, delta);
}

static Long loadOperands(struct Instruction * insn, const UChar * guest_code, Long delta)
{
   assert(insn && guest_code);

   int iOp;
   Long newDelta = delta;
   UChar opcode = guest_code[newDelta];
   Bool flipOperands = False;

   newDelta++;

   enum OperandType operandLoop[3] = {
      insn->encoding->operands.op1,
      insn->encoding->operands.op2,
      insn->encoding->operands.op3
   };

   // The only special case in the 8051 instruction set
   //   Ex. mov (addr), (addr)
   //
   // The addresses are flipped (src, dst vs dst, src)
   // I expected `mov (0x20), (0xe0)` to be encoded as `85 20 e0`
   // but it’s really encoded as `85 e0 20`
   // Good thing I RTFM!
   //
   // Technically this is not correct if we are wanting to go back
   // to the original instruction stream (assemble), but we dont
   // need to do that.
   if(insn->encoding->opcode == MOV &&
         insn->encoding->operands.op1 == OP_DIRECT &&
         insn->encoding->operands.op2 == OP_DIRECT)
   {
      flipOperands = True;
   }

   // For each operand, possibly load some data from the instruction stream
   for(iOp = 0; iOp < 3; iOp++) {
      Long operandDelta = newDelta;
      struct OperandResult * result = &insn->data.op[iOp];

      // Initialize the insn fields
      result->type = operandLoop[iOp];
      result->size = 0;
      result->data.u16 = 0; // it's a union, just zero the biggest field

      switch(operandLoop[iOp]) {
         // Operands that do not require any data
         case NOOP:
         case OP_A:
         case OP_B:
         case OP_DPTR:
         case OP_IDPTR:
         case OP_C:
         case OP_IDRA_DPTR:
         case OP_IDRA_PC:
            break;
         case OP_REG:
         {
            // Opcode{2:0} are the register number
            // Register bank not decided yet
            UChar regN = opcode & 0x7;

            result->data.u8 = regN;
            break;
         }
         case OP_DIRECT:
         {
            // Direct address [0, 255]
            result->data.u8 = guest_code[operandDelta];
            operandDelta++;
            break;
         }
         case OP_OFF:
         {
            // Offset [-128, 127]
            result->data.s8 = guest_code[operandDelta];
            operandDelta++;
            break;
         }
         case OP_ID_REG:
         {
            // Indirect register @R0 or @R1
            result->data.u8 = opcode & 1;
            break;
         }
         case OP_I8:
         {
            // Immediate [0, 255]
            result->data.u8 = guest_code[operandDelta];
            operandDelta++;
            break;
         }
         case OP_I16:
         {
            // Immediate [0, 65535]
            // data16 is stored big-endian
            UShort d16 = (UShort)guest_code[operandDelta] << 8;
            d16 |= guest_code[operandDelta+1];

            result->data.u16 = d16;
            operandDelta += 2;
            break;
         }
         case OP_NBIT: /* fall through */
         case OP_BIT:
         {
            // Bit address [0, 255]
            result->data.u8 = guest_code[operandDelta];
            operandDelta++;
            break;
         }
         case OP_ADDR11:
         {
            UShort d11 = guest_code[operandDelta]; // Addr{7:0} <- Operand{7:0}
            d11 |= (opcode >> 5) << 8; // Addr{10:8} <- Opcode{7:5}

            // Techincally we are size extending this here, but this is just for storage
            result->data.u16 = d11;

            operandDelta++;
            break;
         }
         case OP_ADDR16:
         {
            // Address [0, 65535]
            // addr16 is stored big-endian
            UShort d16 = guest_code[operandDelta] << 8;
            d16 |= guest_code[operandDelta+1];

            result->data.u16 = d16;
            operandDelta += 2;
            break;
         }
         default:
            assert(0);
      } // switch(op)

      if(operandLoop[iOp] != NOOP)
         insn->numOperands++;

      // note the size of the operand and adjust the insn delta
      result->size = operandDelta - newDelta;
      newDelta = operandDelta;

   } // for each operand

   // note the size of the instruction with the delta difference
   insn->size = newDelta - delta;

   if(flipOperands) {
      struct OperandResult tmp = insn->data.op[0];
      insn->data.op[0] = insn->data.op[1];
      insn->data.op[1] = tmp;
   }

   return newDelta;
}


const char * i8051ToStr(enum InstructionOperation op)
{
   switch(op)
   {
      case ACALL:   return "acall";
      case ADD:     return "add";
      case ADDC:    return "addc";
      case AJMP:    return "ajmp";
      case ANL:     return "anl";
      case CJNE:    return "cjne";
      case CLR:     return "clr";
      case CPL:     return "cpl";
      case DA:      return "da";
      case DEC:     return "dec";
      case DIV:     return "div";
      case DJNZ:    return "djnz";
      case INC:     return "inc";
      case JB:      return "jb";
      case JBC:     return "jbc";
      case JC:      return "jc";
      case JMP:     return "jmp";
      case JNB:     return "jnb";
      case JNC:     return "jnc";
      case JNZ:     return "jnz";
      case JZ:      return "jz";
      case LCALL:   return "lcall";
      case LJMP:    return "ljmp";
      case MOV:     return "mov";
      case MOVC:    return "movc";
      case MOVX:    return "movx";
      case MUL:     return "mul";
      case NOP:     return "nop";
      case ORL:     return "orl";
      case POP:     return "pop";
      case PUSH:    return "push";
      case RET:     return "ret";
      case RETI:    return "reti";
      case RL:      return "rl";
      case RLC:     return "rlc";
      case RR:      return "rr";
      case RRC:     return "rrc";
      case SETB:    return "setb";
      case SJMP:    return "sjmp";
      case SUBB:    return "subb";
      case SWAP:    return "swap";
      case XCH:     return "xch";
      case XCHD:    return "xchd";
      case XRL:     return "xrl";
      case INVALID: return "invalid";
      default:
         assert(0);
         return "";
   }
}

void i8051Print(struct Instruction * insn, UChar * string, UInt size)
{
   assert(insn);

   UInt sizeLeft = size;
   UChar * stringPtr = string;
   int i, sz;

#define CHECK_STR do { \
   if(sz < 0) \
     return; \
   if(sizeLeft < sz) \
     return; \
 \
   sizeLeft -= sz; \
   stringPtr += sz; \
   } while(0)

   sz = snprintf(stringPtr, sizeLeft, "%s", i8051ToStr(insn->encoding->opcode));
   CHECK_STR;

   for(i = 0; i < insn->numOperands; i++) {
      sz = snprintf(stringPtr, sizeLeft, " ");
      CHECK_STR;

      struct OperandResult * op = &insn->data.op[i];

      switch(op->type) {
         case OP_A:
         {
            sz = snprintf(stringPtr, sizeLeft, "A");
            break;
         }
         case OP_B:
         {
            sz = snprintf(stringPtr, sizeLeft, "B");
            break;
         }
         case OP_REG:
         {
            sz = snprintf(stringPtr, sizeLeft, "R%hhu", op->data.u8);
            break;
         }
         case OP_DPTR:
         {
            sz = snprintf(stringPtr, sizeLeft, "DPTR");
            break;
         }
         case OP_IDPTR:
         {
            sz = snprintf(stringPtr, sizeLeft, "@DPTR");
            break;
         }
         case OP_C:
         {
            sz = snprintf(stringPtr, sizeLeft, "C");
            break;
         }
         case OP_DIRECT:
         {
            sz = snprintf(stringPtr, sizeLeft, "(0x%x)", op->data.u8);
            break;
         }
         case OP_OFF:
         {
            sz = snprintf(stringPtr, sizeLeft, "$%d", op->data.s8);
            break;
         }
         case OP_ID_REG:
         {
            sz = snprintf(stringPtr, sizeLeft, "@R%hhu", op->data.u8);
            break;
         }
         case OP_I8:
         {
            sz = snprintf(stringPtr, sizeLeft, "#0x%02x", op->data.u8);
            break;
         }
         case OP_I16:
         {
            sz = snprintf(stringPtr, sizeLeft, "#0x%04x", op->data.u16);
            break;
         }
         case OP_NBIT: /* fall through */
         case OP_BIT:
         {
            UChar byte = 0;
            UChar bit = op->data.u8 & 0x7;

            if(op->data.u8 < 0x80) { // accessing RAM with base of 0x20
               byte = 0x20 + (op->data.u8 >> 3);
            } else { // accessing SFRs every 8 bytes (base of 0x80)
               byte = op->data.u8 & ~0x7;
            }

            sz = snprintf(stringPtr, sizeLeft, "%s(0x%02x).%hhu",
                  (op->type == OP_NBIT) ? "/" : "",
                  byte, bit
            );
            break;
         }
         case OP_ADDR11:
         {
            UChar page = (op->data.u16 >> 8) & 0x7;
            UChar offset = op->data.u16 & 0xff;
            sz = snprintf(stringPtr, sizeLeft, "(P%u+0x%02x)", page, offset);
            break;
         }
         case OP_ADDR16:
         {
            sz = snprintf(stringPtr, sizeLeft, "0x%04x", op->data.u16);
            break;
         }
         case OP_IDRA_DPTR:
         {
            sz = snprintf(stringPtr, sizeLeft, "@A + DPTR");
            break;
         }
         case OP_IDRA_PC:
         {
            sz = snprintf(stringPtr, sizeLeft, "@A + PC");
            break;
         }
         default:
            assert(0);
      } // end switch operand type

      CHECK_STR;

      // should we have a comma?
      if(i+1 != insn->numOperands)
         sz = snprintf(stringPtr, sizeLeft, ",");

      CHECK_STR;
   }

   return;
}

/*--------------------------------------------------------------------*/
/*--- end                                      guest_8051_disasm.c ---*/
/*--------------------------------------------------------------------*/
