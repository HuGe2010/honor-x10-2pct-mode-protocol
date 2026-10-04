#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反汇编 update-binary 中的协议函数，提取常量与调用关系"""
import sys
import os

sys.path.insert(0, r"C:\Program Files\Python312\Lib\site-packages")
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

BIN = r"C:\hx10_research\binaries\update-binary-ours"
OUT = r"C:\hx10_research\reports"

TARGETS = [
    ("new_process_shake_hand_cmd", 0x410DFC, 96),
    ("new_process_update_auth_cmd", 0x411208, 96),
    ("get_total_pkg_size_cmd", 0x410AC0, 428),
    ("process_data_thread", 0x410218, 748),
    ("process_read_data_thread", 0x419C98, 980),
    ("change_to_usb_dload_mode", 0x3EE1C8, 388),
    ("ConnectAndSendCmd", 0x45E398, 240),
    ("ConnectAndSendCmdForReused", 0x45E948, 260),
    ("update_from_zip_module_processdata", 0x4080CC, 480),
    ("ProcRecvDataFunction", 0x3D7460, 656),
    ("huawei_write_raw_data", 0x3D98F8, 340),
]


def build_map(path):
    """建立 vaddr -> file offset 映射（按 PT_LOAD 段）"""
    segs = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                segs.append((seg["p_vaddr"], seg["p_vaddr"] + seg["p_filesz"],
                             seg["p_offset"]))
    return segs


def v2o(segs, vaddr):
    for va, vend, off in segs:
        if va <= vaddr < vend:
            return off + (vaddr - va)
    return None


def disasm(segs, data, name, addr, size):
    off = v2o(segs, addr)
    if off is None:
        return ["  [!] 地址 0x%x 不在任何 PT_LOAD 段内" % addr]
    code = data[off:off + size]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    lines = []
    lines.append("=== %s  @ 0x%x  (%d 字节, 文件偏移 0x%x)" % (name, addr, size, off))
    for ins in md.disasm(code, addr):
        extra = ""
        # 提取立即数
        for op in ins.operands:
            if op.type == 2:  # IMM
                extra += " imm=0x%x(%d)" % (op.imm & 0xFFFFFFFFFFFFFFFF, op.imm)
        lines.append("  %08x  %-8s %-30s%s" % (ins.address, ins.mnemonic, ins.op_str, extra))
    lines.append("")
    return lines


def main():
    with open(BIN, "rb") as f:
        data = f.read()
    segs = build_map(BIN)
    print("PT_LOAD 段:")
    for va, vend, off in segs:
        print("  0x%x - 0x%x  file_off=0x%x" % (va, vend, off))

    allout = []
    for name, addr, size in TARGETS:
        lines = disasm(segs, data, name, addr, size)
        allout += lines
        print("\n".join(lines))

    outp = os.path.join(OUT, "disasm-protocol.txt")
    with open(outp, "w", encoding="utf-8") as f:
        f.write("\n".join(allout))
    print("\n已存: %s" % outp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
