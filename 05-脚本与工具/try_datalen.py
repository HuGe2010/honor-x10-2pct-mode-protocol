#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
★ 验证 dwDataLen 上限假说
   OTA_ZIP + startAddr 固定，变化 dwDataLen，从大到小
   每次失败后发包尾(0x43)重置
"""
import sys
import os
import time
import struct
import serial

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass

sys.path.insert(0, r"C:\hx10_research")
from flash import (module_head, cmd_handshake, cmd_head, cmd_tail, find_port, rd)

# (模块名, startAddr, dataLen)
VARIANTS = [
    ("OTA_ZIP", 0xBA000000, 0x04800000),   # 72MB  ← 表里的值
    ("OTA_ZIP", 0xBA000000, 0x00800000),   # 8MB
    ("OTA_ZIP", 0xBA000000, 0x00400000),   # 4MB
    ("OTA_ZIP", 0xBA000000, 0x00100000),   # 1MB
    ("OTA_ZIP", 0xBA000000, 0x00040000),   # 256KB
    ("OTA_ZIP", 0xBA000000, 0x00001000),   # 4KB
    ("OTA_ZIP", 0xBA000000, 0x00000000),   # 0
    ("OTA_ZIP", 0x00000000, 0x00001000),   # 换 startAddr
    ("OTA_ZIP", 0x00000000, 0x00400000),
]


def main():
    dev = find_port()
    if not dev:
        print("❌ 手机不在升级模式")
        return 1
    print("端口 %s" % dev)

    sp = serial.Serial(port=dev, baudrate=9600, timeout=1,
                       bytesize=8, parity="N", stopbits=1, write_timeout=8)
    try:
        print("[0] 握手 ...")
        sp.reset_input_buffer()
        sp.write(cmd_handshake())
        sp.flush()
        r = rd(sp, 3)
        print("    -> %s" % (r.hex() if r else "❌ 无响应"))
        if not r:
            return 1

        print("\n=== dwDataLen 递减测试 ===")
        for name, start, dlen in VARIANTS:
            hdr = module_head(name, dlen, start_addr=start)
            sp.reset_input_buffer()
            sp.write(cmd_head(hdr))
            sp.flush()
            r = rd(sp, 2.5)
            if not r:
                print("  %-10s start=0x%08X len=0x%08X  ★★★ 无 ACK —— 通过！" % (name, start, dlen))
                return 0
            code = r[1] if len(r) > 1 else -1
            print("  %-10s start=0x%08X len=0x%08X  ACK码=0x%02X %s" % (
                name, start, dlen, code, "← 失败" if code else ""))
            sp.write(cmd_tail(hdr))
            sp.flush()
            rd(sp, 1.2)
        print("\n全部被拒")
    finally:
        try:
            sp.close()
        except Exception:
            pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
