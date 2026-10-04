#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反汇编所有协议命令处理函数，提取操作码常量"""
import sys
import os
import re

sys.path.insert(0, r"C:\Program Files\Python312\Lib\site-packages")
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

BIN = r"C:\hx10_research\binaries\update-binary-ours"
SYMS = r"C:\hx10_research\reports\symbols-ours.txt"
OUT = r"C:\hx10_research\reports"

HANDLERS = [
    ("handshake_cmd", 0x3EC860, 540),
    ("unlock_cmd", 0x3ECA7C, 228),
    ("cmd_update_auth_func", 0x3EC4C0, 928),
    ("new_shake_hand_cmd", 0x410504, 120),
    ("reboot_device_cmd", 0x41057C, 212),
    ("force_reboot_device_cmd", 0x410650, 224),
    ("unlock_device_cmd", 0x41089C, 228),
    ("transmit_write_cmd", 0x410730, 364),
    ("transmit_write_begin_cmd", 0x410980, 112),
    ("transmit_write_post_cmd", 0x4109F0, 88),
    ("cmd_unit_write_post_func", 0x3ED9D0, 520),
    ("send_package", 0x3F536C, 760),
    ("RecvPackage", 0x3F4F78, 612),
    ("ReceivePackage", 0x40FCE0, 1336),
    ("change_to_usb_dload_mode", 0x3EE1C8, 388),
]


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


def main():
    data, segs = load()
    syms = load_syms()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    res = []

    for name, addr, size in HANDLERS:
        res.append("\n" + "=" * 70)
        res.append("### %s  @0x%x  (%d 字节)" % (name, addr, size))
        res.append("=" * 70)
        o = v2o(segs, addr)
        if o is None:
            res.append("  [!] 地址不在 PT_LOAD")
            continue
        for ins in md.disasm(data[o:o + size], addr):
            line = "  %08x  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str)
            consts = []
            if ins.mnemonic in ("cmp", "mov", "movz", "movk", "and", "orr", "tst", "ubfx", "movn"):
                for op in ins.operands:
                    if op.type == 2:
                        consts.append("0x%x" % (op.imm & 0xFFFFFFFF))
            if consts:
                line += "      ; " + " ".join(consts)
            if ins.mnemonic == "bl":
                m = re.match(r"#(0x[0-9a-f]+)", ins.op_str)
                if m:
                    t = int(m.group(1), 16)
                    if t in syms:
                        line += "      ; -> %s" % syms[t][1][:70]
            res.append(line)

    txt = "\n".join(res)
    open(os.path.join(OUT, "handlers-disasm.txt"), "w", encoding="utf-8").write(txt)
    print("已存: %s" % os.path.join(OUT, "handlers-disasm.txt"))
    print("总行数: %d" % len(res))

    # 打印关键的小 handler
    for name, addr, size in HANDLERS:
        if size <= 400:
            res2 = []
            o = v2o(segs, addr)
            res2.append("\n### %s @0x%x" % (name, addr))
            for ins in md.disasm(data[o:o + size], addr):
                line = "  %08x  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str)
                if ins.mnemonic == "bl":
                    m = re.match(r"#(0x[0-9a-f]+)", ins.op_str)
                    if m and int(m.group(1), 16) in syms:
                        line += "   -> %s" % syms[int(m.group(1), 16)][1][:60]
                res2.append(line)
            sys.stdout.buffer.write(("\n".join(res2) + "\n").encode("utf-8", errors="replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
