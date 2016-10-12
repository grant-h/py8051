"""
Python bindings for 8051 disassembler
"""
import os
import sys
import cffi
import pkg_resources

ffi_str = """
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
   OP_BIT, OP_NBIT, /* For accessing special bit addresses */
   OP_ADDR11, OP_ADDR16, /* Address 11-bits, 16-bits */
   OP_IDRA_DPTR, OP_IDRA_PC /* Special relative calculations: @A+DPTR, @A+PC */
};
struct InstructionOperands {
   enum OperandType op1;
   enum OperandType op2;
   enum OperandType op3;
};
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
"""

ffi = cffi.FFI()

def _find_c_lib():
    # Load the c library
    if sys.platform == 'darwin':
        library_file = "libpy8051.dylib"
    else:
        library_file = "libpy8051.so"

    py8051_path = pkg_resources.resource_filename(__name__, os.path.join('lib', library_file))

    ffi.cdef(ffi_str)

    lib = ffi.dlopen(py8051_path)

    # this looks up all the definitions (wtf)
    dir(lib)
    return lib

p8051c = _find_c_lib()

class Py8051Insn(object):
    def __init__(self, addr, mnemonic, op_str, size):
        self.address = addr
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.size = size

    def __repr__(self):
        return '<Py8051Insn "%s" for %#x>' % (self.mnemonic, self.address)

    def __str__(self):
        return '%#x\t%s\t%s' % (self.address, self.mnemonic, self.op_str)

def disasm(ibytes, addr):
    newAddr = addr
    delta = 0

    while delta < len(ibytes):
        insn = ffi.new('struct Instruction *')
        code = ffi.new('UChar[]', ibytes)

        newDelta = p8051c.i8051DecodeInsn(insn, code, delta)

        # we didnt have enough bytes to read a complete instruction
        # stop here
        if newDelta > len(ibytes):
            break

        difference = newDelta - delta

        outString = ffi.new('UChar[25]')
        p8051c.i8051Print(insn, outString, len(outString)-1)
        insnString = ffi.string(outString)

        spacePos = insnString.find(' ')

        # This instruction has at least one operand
        if spacePos != -1:
            yield Py8051Insn(newAddr,
                    insnString[0:spacePos],
                    insnString[spacePos+1:],
                    difference)
        else:
            yield Py8051Insn(newAddr, insnString, "", difference)

        newAddr += difference
        delta = newDelta

if __name__ == "__main__":
    # test on firmware disasm
    firmware = open('firmware.bin', 'rb').read()

    for i in disasm(firmware, 0):
        print i

    for i in disasm("\x00\x02\xeb\xfe\xba\x01\x20\xaa\x01", 0):
        print i








