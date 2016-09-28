# Py8051

# Installing Py8051

Py8051 can be pip-installed:

```bash
pip install py8051
```

# Using Py8051

Py8051 creates an interface to an 8051 disassembler that is also used in VEX.

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
