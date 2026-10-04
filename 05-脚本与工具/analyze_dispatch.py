#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1) 找 pkg_process 相关符号
2) dump 0x535708 附近的函数指针表（命令分发表）
3) 完整反汇编 process_data_thread 找 opcode 比较
"""
import sys
import os
import struct
import re
import io

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


def main():
    data, segs = load()
    out = []

    # 1) 符号表里找 pkg_process / 相关
    syms = {}
    for ln in open(SYMS, encoding="utf-8", errors="replace"):
        m = re.match(r"\s*\d+\s+0x([0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$", ln)
        if m:
            syms[int(m.group(1), 16)] = (int(m.group(2)), m.group(6).strip())

    out.append("########## 1) 含 pkg_process / process 表的符号 ##########")
    for a, (sz, n) in sorted(syms.items()):
        if "pkg_process" in n or "process_table" in n or "cmd_table" in n or "handle" in n.lower():
            out.append("  0x%08x  size=%-6d %s" % (a, sz, n))

    # 2) dump 0x535708 附近
    out.append("\n########## 2) 0x535000-0x535900 区域（找函数指针表）##########")
    start, end = 0x535000, 0x535900
    off = v2o(segs, start)
    if off is not None:
        out.append("  文件偏移 0x%x" % off)
        for i in range(0, end - start, 8):
            v = struct.unpack_from("<Q", data, off + i)[0]
            if v == 0:
                out.append("    +0x%03x  0" % i)
                continue
            name = syms.get(v, (None, None))[1]
            mark = "  <-- %s" % name if name else ""
            intext = any(va <= v < vend for va, vend, _ in segs)
            out.append("    +0x%03x  0x%016x%s%s" % (i, v, "  (有效地址)" if intext else "", mark))

    # 3) 完整反汇编 process_data_thread，高亮 cmp/mov 常量
    out.append("\n########## 3) process_data_thread 完整反汇编 ##########")
    addr, size = 0x410218, 748
    o = v2o(segs, addr)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    for ins in md.disasm(data[o:o + size], addr):
        line = "  %08x  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str)
        # 标注立即数
        if ins.mnemonic in ("cmp", "mov", "movz", "movk", "and", "orr", "tst", "ubfx", "lsl", "lsr"):
            for op in ins.operands:
                if op.type == 2:
                    line += "      ; imm=0x%x" % (op.imm & 0xFFFFFFFF)
        # 标注 bl 目标
        if ins.mnemonic == "bl":
            m = re.match(r"#(0x[0-9a-f]+)", ins.op_str)
            if m:
                t = int(m.group(1), 16)
                nm = syms.get(t, (None, None))[1]
                if nm:
                    line += "      ; -> %s" % nm
        out.append(line)

    txt = "\n".join(out)
    with open(os.path.join(OUT, "dispatch-analysis.txt"), "w", encoding="utf-8") as f:
        f.write(txt)
    # 安全输出（避免 GBK 错误）
    sys.stdout.buffer.write(txt.encode("utf-8", errors="replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
