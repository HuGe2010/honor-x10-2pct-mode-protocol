#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
找命令分发器：搜索所有 cmp wN, #0x2XX 形式的 16 位命令比较，
并定位调用 new_process_* / *_cmd 的地方。
"""
import sys, os, re, struct
sys.path.insert(0, r"C:\Program Files\Python312\Lib\site-packages")
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

BIN = r"C:\hx10_research\binaries\update-binary-ours"
SYMS = r"C:\hx10_research\reports\symbols-ours.txt"
OUT = r"C:\hx10_research\reports"


def main():
    data = open(BIN, "rb").read()
    segs = []
    for s in ELFFile(open(BIN, "rb")).iter_segments():
        if s["p_type"] == "PT_LOAD":
            segs.append((s["p_vaddr"], s["p_vaddr"] + s["p_filesz"], s["p_offset"]))

    syms = {}
    for ln in open(SYMS, encoding="utf-8", errors="replace"):
        m = re.match(r"\s*\d+\s+0x([0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$", ln)
        if m:
            syms[int(m.group(1), 16)] = (int(m.group(2)), m.group(6).strip())

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    def sym_at(a):
        best = None
        for sa, (sz, n) in syms.items():
            if sa <= a < sa + max(sz, 4) and sz > 0:
                if best is None or sa > best[0]:
                    best = (sa, n)
        return best[1] if best else None

    # 1) 找 16 位命令比较（0x200-0x2FF 区间）
    print("=== 16位命令比较 (0x2xx) ===")
    hits = {}
    for va, ve, off in segs:
        code = data[off:off + (ve - va)]
        for ins in md.disasm(code, va):
            if ins.mnemonic == "cmp" and len(ins.operands) == 2:
                if ins.operands[1].type == 2:
                    imm = ins.operands[1].imm
                    if 0x200 <= imm <= 0x2FF:
                        hits.setdefault(imm, []).append(ins.address)
    for imm in sorted(hits):
        fns = set(sym_at(a) or "0x%x" % a for a in hits[imm])
        print("  0x%03X  出现 %d 次   %s" % (imm, len(hits[imm]), ", ".join(sorted(fns))[:90]))

    # 2) 找对命令 handler 的调用（间接或直接）
    print("\n=== 命令 handler 符号 ===")
    for a, (sz, n) in sorted(syms.items()):
        if any(k in n for k in ["new_process_", "new_shake", "reboot_device_cmd",
                                "force_reboot_device_cmd", "unlock_device_cmd",
                                "transmit_write_cmd", "transmit_write_begin",
                                "transmit_write_post", "get_total_pkg_size_cmd",
                                "process_data_thread", "handshake_cmd", "unlock_cmd"]):
            print("  0x%08x  %5d  %s" % (a, sz, n))

    # 3) 反汇编 process_data_thread 里 cmp 区域
    print("\n=== process_data_thread 0x410300-0x410330 细节 ===")
    o = None
    for va, ve, off in segs:
        if va <= 0x410300 < ve:
            o = off + (0x410300 - va)
    if o:
        for ins in md.disasm(data[o:o + 0x40], 0x410300):
            print("  %08x  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
