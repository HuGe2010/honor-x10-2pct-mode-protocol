#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1) 解析反汇编里 adrp+add 引用的字符串
2) 在二进制里搜索 handler 地址的 8 字节 LE 模式（找函数指针表/分发器）
"""
import sys
import os
import struct
import re

sys.path.insert(0, r"C:\Program Files\Python312\Lib\site-packages")
from elftools.elf.elffile import ELFFile

BIN = r"C:\hx10_research\binaries\update-binary-ours"
OUT = r"C:\hx10_research\reports"

HANDLERS = {
    "new_process_shake_hand_cmd": 0x410DFC,
    "new_process_update_auth_cmd": 0x411208,
    "get_total_pkg_size_cmd": 0x410AC0,
    "process_data_thread": 0x410218,
    "process_read_data_thread": 0x419C98,
    "change_to_usb_dload_mode": 0x3EE1C8,
    "ConnectAndSendCmd": 0x45E398,
    "ConnectAndSendCmdForReused": 0x45E948,
    "update_from_zip_module_processdata": 0x4080CC,
    "ProcRecvDataFunction": 0x3D7460,
    "huawei_write_raw_data": 0x3D98F8,
}


def load():
    with open(BIN, "rb") as f:
        data = f.read()
    segs = []
    with open(BIN, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                segs.append((seg["p_vaddr"], seg["p_vaddr"] + seg["p_filesz"], seg["p_offset"]))
    return data, segs


def v2o(segs, v):
    for va, vend, off in segs:
        if va <= v < vend:
            return off + (v - va)
    return None


def read_cstr(data, segs, v, maxlen=200):
    off = v2o(segs, v)
    if off is None:
        return None
    end = data.find(b"\x00", off)
    if end < 0 or end - off > maxlen:
        end = off + maxlen
    try:
        return data[off:end].decode("utf-8", errors="replace")
    except Exception:
        return None


def main():
    data, segs = load()

    # 1) 搜索 handler 地址（8 字节 LE）和 BL 指令
    print("########## 1) 搜索 handler 地址引用 ##########")
    for name, addr in HANDLERS.items():
        pat8 = struct.pack("<Q", addr)
        hits = [m.start() for m in re.finditer(re.escape(pat8), data)]
        # BL 指令: 0x94000000 | ((target - pc) >> 2)
        bl_hits = []
        for off in range(0, len(data) - 4, 4):
            ins = struct.unpack_from("<I", data, off)[0]
            if (ins & 0xFC000000) == 0x94000000:
                imm = ins & 0x03FFFFFF
                if imm & 0x02000000:
                    imm -= 0x04000000
                # 计算 vaddr
                pc_v = None
                for va, vend, foff in segs:
                    if foff <= off < foff + (vend - va):
                        pc_v = va + (off - foff)
                        break
                if pc_v is None:
                    continue
                if pc_v + imm * 4 == addr:
                    bl_hits.append(pc_v)
        print("\n  %s (0x%x)" % (name, addr))
        if hits:
            print("     指针表出现 %d 次:" % len(hits))
            for h in hits[:6]:
                # 反查 vaddr
                for va, vend, foff in segs:
                    if foff <= h < foff + (vend - va):
                        print("        文件偏移 0x%x  ->  vaddr 0x%x" % (h, va + (h - foff)))
                        break
        if bl_hits:
            print("     BL 调用点 %d 个:" % len(bl_hits))
            for b in bl_hits[:6]:
                print("        0x%x" % b)

    # 2) 解析 disasm 里的字符串引用
    print("\n\n########## 2) 解析 adrp+add 引用的字符串 ##########")
    dis = os.path.join(OUT, "disasm-protocol.txt")
    if not os.path.exists(dis):
        print("  缺 disasm 文件")
        return 1
    lines = open(dis, encoding="utf-8").read().splitlines()
    cur = None
    pend = {}
    seen = set()
    for ln in lines:
        if ln.startswith("==="):
            cur = ln
            pend = {}
            continue
        m = re.match(r"\s+([0-9a-f]{8})\s+adrp\s+(x\d+|w\d+),\s+#(0x[0-9a-f]+)", ln)
        if m:
            pend[m.group(2)] = int(m.group(3), 16)
            continue
        m = re.match(r"\s+([0-9a-f]{8})\s+add\s+(x\d+|w\d+),\s+\2,\s+#(0x[0-9a-f]+)", ln)
        if m and m.group(2) in pend:
            addr = pend[m.group(2)] + int(m.group(3), 16)
            s = read_cstr(data, segs, addr)
            if s and s not in seen and len(s) > 2:
                seen.add(s)
                print("  %-45s -> 0x%x  %r" % (cur.replace("===", "").strip()[:45], addr, s))
            pend.pop(m.group(2), None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
