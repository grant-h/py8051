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
