from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(b"\x90\x90", 0x1000):
    print(insn.mnemonic)
