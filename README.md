# py8051
A full 8051 disassembler written in C. Python bindings are provided for quick and easy use, but the underlying C files can be extracted and used as their own library.
The python bindings provide a Capstone-like interface for printing disassembled instructions. You are also able to print the mnemonic and operands separately.

# Installing py8051

py8051 can be pip-installed:

```bash
pip install py8051
```

# Using py8051

py8051 creates an interface to a C-based 8051 disassembler.

```python
import py8051

# Print all decoded instructions with their address and full instruction text
# py8051.disasm(instructions.str, start_address)
for insn in py8051.disasm("\x00\x02\xeb\xfe\xba\x01\x20\xaa\x01", 0x0000):
    print(insn)

# Break instructions down by mnemonic and operands
for insn in py8051.disasm("\x00\x02\xeb\xfe\xba\x01\x20\xaa\x01", 0x0000):
    ops = insn.op_str.split(',') # split operands
    ops = [o.strip() for o in ops] # strip whitespace
    separated_ops = []

    for i, op in enumerate(ops):
        separated_ops += ["%d[%s]" % (i, op)]

    print("0x%04x Mnemonic[%4s] -- Operands %-25s -- Full String '%s'" %
            (insn.address, insn.mnemonic, " ".join(separated_ops), insn))
```

The above prints:

```
0x1     ljmp    0xebfe
0x4     cjne    R2, #0x01, $32
0x7     mov     R2, (0x1)
0x0000 Mnemonic[ nop] -- Operands 0[]                       -- Full String '0x0 nop     '
0x0001 Mnemonic[ljmp] -- Operands 0[0xebfe]                 -- Full String '0x1 ljmp    0xebfe'
0x0004 Mnemonic[cjne] -- Operands 0[R2] 1[#0x01] 2[$32]     -- Full String '0x4 cjne    R2, #0x01, $32'
0x0007 Mnemonic[ mov] -- Operands 0[R2] 1[(0x1)]            -- Full String '0x7 mov     R2, (0x1)'
```

## Notes
This has only been tested on Ubuntu 16.04 and it requires a working GCC compiler.
Some interesting features that I want to add would be to replace addresses in direct memory accesses with names.
