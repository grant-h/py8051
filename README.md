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

for insn in py8051.disasm("\x00\x02\xeb\xfe\xba\x01\x20\xaa\x01", 0):
    print(insn)
```

The above prints:

```
0x0     nop
0x1     ljmp    0xebfe
0x4     cjne    R2, #0x01, $32
0x7     mov     R2, (0x1)
```

## Notes
This has only been tested on Ubuntu 16.04 and it requires a working GCC compiler.
Some interesting features that I want to add would be to replace addresses in direct memory accesses with names.
