#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反汇编 send_package 和 opcode 分发区域，并搜索全部命令处理函数"""
import sys
import os
import re
import struct

sys.path.insert(0, r"C:\Program Files\Python312\Lib\site-packages")
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

BIN = r"C:\hx10_research\binaries\update-binary-ours"
SYMS = r"C:\hx10_research\reports\symbols-ours.txt"
OUT = r"C:\hx10_research\reports"


def load():
    data = open(BIN, "rb").read()
    segs = []
    elf = ELFFile(open(BIN, "rb"))
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD":
            segs.append((seg["p_vaddr"], seg["p_vaddr"] + seg["p_filesz"], seg["p_offset"]))
    return data, segs


def v2o(segs, v):
    for va, vend, off in segs:
        if va <= v < vend:
            return off + (v - va)
    return None


def load_syms():
    syms = {}
    for ln in open(SYMS, encoding="utf-8", errors="replace"):
        m = re.match(r"\s*\d+\s+0x([0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$", ln)
        if m:
            syms[int(m.group(1), 16)] = (int(m.group(2)), m.group(6).strip())
    return syms


def dis(data, segs, syms, addr, size, title):
    out = ["\n########## %s  @0x%x (%d 字节) ##########" % (title, addr, size)]
    o = v2o(segs, addr)
    if o is None:
        out.append("  [!] 地址不在 PT_LOAD 段")
        return out
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    for ins in md.disasm(data[o:o + size], addr):
        line = "  %08x  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str)
        if ins.mnemonic in ("cmp", "mov", "movz", "movk", "and", "orr", "tst", "ubfx"):
            for op in ins.operands:
                if op.type == 2:
                    line += "    ; #0x%x" % (op.imm & 0xFFFFFFFF)
        if ins.mnemonic == "bl":
            m = re.match(r"#(0x[0-9a-f]+)", ins.op_str)
            if m:
                t = int(m.group(1), 16)
                if t in syms:
                    line += "    ; -> %s" % syms[t][1]
        out.append(line)
    return out


def main():
    data, segs = load()
    syms = load_syms()
    res = []

    # 1) 所有命令/包相关函数
    res.append("########## 命令与包处理相关符号 ##########")
    kws = ["send_package", "send_ack", "recv", "cmd", "package", "pkg_size",
           "shake", "auth", "process_data", "pool_", "usb_dload", "dload_mode"]
    for a, (sz, n) in sorted(syms.items()):
        low = n.lower()
        if any(k in low for k in kws) and sz > 0:
            res.append("  0x%08x  size=%-6d %s" % (a, sz, n))

    # 2) 反汇编 send_package
    sp = None
    for a, (sz, n) in syms.items():
        if n == "send_package":
            sp = (a, sz)
    if sp:
        res += dis(data, segs, syms, sp[0], sp[1], "send_package")

    # 3) opcode 分发区域
    res += dis(data, segs, syms, 0x4102E0, 0x80, "opcode 分发区域")

    # 4) 全局搜索 cmp wN, #0x41/#0x43/#0x44 的位置
    res.append("\n########## 全局搜索 opcode 比较 (0x41/0x43/0x44/0x0f/0x0b/0x0a/0x32) ##########")
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    targets = {0x41: "HEAD('A')", 0x43: "TAIL('C')", 0x44: "0x44('D')",
               0x0F: "DATA", 0x0B: "UNLOCK", 0x0A: "REBOOT", 0x32: "FORCEREBOOT"}
    hits = {}
    for va, vend, off in segs:
        code = data[off:off + (vend - va)]
        for ins in md.disasm(code, va):
            if ins.mnemonic == "cmp" and len(ins.operands) == 2:
                if ins.operands[1].type == 2:
                    imm = ins.operands[1].imm
                    if imm in targets:
                        hits.setdefault(imm, []).append(ins.address)
    for imm, desc in sorted(targets.items()):
        addrs = hits.get(imm, [])
        res.append("  0x%02x %-14s 出现 %d 次" % (imm, desc, len(addrs)))
        for a in addrs[:8]:
            fn = None
            for sa, (sz, n) in sorted(syms.items()):
                if sa <= a < sa + max(sz, 4) and sz > 0:
                    fn = n
            res.append("      0x%08x  %s" % (a, fn or ""))

    txt = "\n".join(res)
    open(os.path.join(OUT, "send-package-analysis.txt"), "w", encoding="utf-8").write(txt)
    sys.stdout.buffer.write(txt.encode("utf-8", errors="replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
