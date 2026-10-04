#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反汇编 update_from_zip_module_* 系列，解析 zip 传输协议"""
import sys, os, re
sys.path.insert(0, r"C:\Program Files\Python312\Lib\site-packages")
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

BIN = r"C:\hx10_research\binaries\update-binary-ours"
SYMS = r"C:\hx10_research\reports\symbols-ours.txt"
OUT = r"C:\hx10_research\reports"

TARGETS = [
    ("update_from_zip_module_begin", 0x407F24, 424),
    ("update_from_zip_module_processdata", 0x4080CC, 480),
    ("update_from_zip_module_post", 0x4082AC, 244),
    ("update_from_zip_module_skipdata", 0x4083A0, 300),
]


def main():
    data = open(BIN, "rb").read()
    segs = []
    for s in ELFFile(open(BIN, "rb")).iter_segments():
        if s["p_type"] == "PT_LOAD":
            segs.append((s["p_vaddr"], s["p_vaddr"] + s["p_filesz"], s["p_offset"]))

    def v2o(v):
        for va, ve, off in segs:
            if va <= v < ve:
                return off + (v - va)
        return None

    def cstr(v, n=100):
        o = v2o(v)
        if o is None:
            return None
        e = data.find(b"\x00", o)
        if e < 0 or e - o > n:
            return None
        try:
            return data[o:e].decode("utf-8")
        except Exception:
            return None

    syms = {}
    for ln in open(SYMS, encoding="utf-8", errors="replace"):
        m = re.match(r"\s*\d+\s+0x([0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$", ln)
        if m:
            syms[int(m.group(1), 16)] = (int(m.group(2)), m.group(6).strip())

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    out = []
    for name, addr, size in TARGETS:
        out.append("\n" + "=" * 62)
        out.append("### %s @0x%x (%d 字节)" % (name, addr, size))
        out.append("=" * 62)
        o = v2o(addr)
        pend = {}
        for ins in md.disasm(data[o:o + size], addr):
            line = "  %08x  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str)
            consts = []
            if ins.mnemonic in ("cmp", "mov", "movz", "movk", "and", "orr", "tst", "ubfx", "ldrb", "ldrh", "ldr", "str", "strb", "strh"):
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
                        line += "    -> %s" % syms[t][1][:60]
            # 解析 adrp+add 字符串
            m = re.match(r"adrp\s+(x\d+),\s+#(0x[0-9a-f]+)", ins.mnemonic + " " + ins.op_str)
            if m:
                pend[m.group(1)] = int(m.group(2), 16)
            m = re.match(r"add\s+(x\d+),\s+\1,\s+#(0x[0-9a-f]+)", ins.mnemonic + " " + ins.op_str)
            if m and m.group(1) in pend:
                s = cstr(pend[m.group(1)] + int(m.group(2), 16))
                if s:
                    line += "      ; STR=%r" % s[:60]
                pend.pop(m.group(1), None)
            out.append(line)
    txt = "\n".join(out)
    open(os.path.join(OUT, "zipmodule-disasm.txt"), "w", encoding="utf-8").write(txt)
    sys.stdout.buffer.write(txt.encode("utf-8", errors="replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
