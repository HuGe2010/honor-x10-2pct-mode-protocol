#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, os, re
sys.path.insert(0, r"C:\Program Files\Python312\Lib\site-packages")
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

BIN = r"C:\hx10_research\binaries\update-binary-ours"
SYMS = r"C:\hx10_research\reports\symbols-ours.txt"
OUT = r"C:\hx10_research\reports"

TARGETS = [
    ("transmit_packet", 0x3F4CD4, 184),
    ("transmit_byte", 0x3F4D8C, 300),
    ("transmit_response", 0x3F4EB8, 192),
]


def main():
    data = open(BIN, "rb").read()
    segs = []
    for seg in ELFFile(open(BIN, "rb")).iter_segments():
        if seg["p_type"] == "PT_LOAD":
            segs.append((seg["p_vaddr"], seg["p_vaddr"] + seg["p_filesz"], seg["p_offset"]))

    syms = {}
    for ln in open(SYMS, encoding="utf-8", errors="replace"):
        m = re.match(r"\s*\d+\s+0x([0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$", ln)
        if m:
            syms[int(m.group(1), 16)] = (int(m.group(2)), m.group(6).strip())

    def v2o(v):
        for va, vend, off in segs:
            if va <= v < vend:
                return off + (v - va)
        return None

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    out = []
    for name, addr, size in TARGETS:
        out.append("\n" + "=" * 60)
        out.append("### %s @0x%x (%d 字节)" % (name, addr, size))
        out.append("=" * 60)
        o = v2o(addr)
        for ins in md.disasm(data[o:o + size], addr):
            line = "  %08x  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str)
            consts = []
            if ins.mnemonic in ("cmp", "mov", "movz", "movk", "and", "orr", "tst", "ubfx"):
                for op in ins.operands:
                    if op.type == 2:
                        consts.append("0x%x" % (op.imm & 0xFFFFFFFF))
            if consts:
                line += "    ; " + " ".join(consts)
            if ins.mnemonic == "bl":
                m = re.match(r"#(0x[0-9a-f]+)", ins.op_str)
                if m:
                    t = int(m.group(1), 16)
                    if t in syms:
                        line += "    -> %s" % syms[t][1][:70]
            out.append(line)
    txt = "\n".join(out)
    open(os.path.join(OUT, "transmit-disasm.txt"), "w", encoding="utf-8").write(txt)
    sys.stdout.buffer.write(txt.encode("utf-8", errors="replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
