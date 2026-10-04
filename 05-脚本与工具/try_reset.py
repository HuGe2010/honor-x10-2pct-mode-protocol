#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
★ 每次尝试前重发握手，看能否重置状态 —— 这样能在一个会话里测多个长度
"""
import sys
import os
import time
import serial

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass

sys.path.insert(0, r"C:\hx10_research")
from flash import (module_head, cmd_handshake, cmd_head, cmd_tail, find_port, rd)

# 从大到小
VARIANTS = [
    ("OTA_ZIP", 0xBA000000, 0x04800000),
    ("OTA_ZIP", 0xBA000000, 0x01000000),
    ("OTA_ZIP", 0xBA000000, 0x00400000),
    ("OTA_ZIP", 0xBA000000, 0x00100000),
    ("OTA_ZIP", 0xBA000000, 0x00010000),
    ("OTA_ZIP", 0xBA000000, 0x00001000),
    ("OTA_ZIP", 0x00000000, 0x00001000),
    ("OTA_ZIP", 0x00000000, 0x00400000),
    ("OTA_ZIP", 0x04800000, 0x00001000),
]


def hs(sp):
    sp.reset_input_buffer()
    sp.write(cmd_handshake())
    sp.flush()
    return rd(sp, 2)


def main():
    dev = find_port()
    if not dev:
        print("❌ 手机不在升级模式")
        return 1
    print("端口 %s" % dev)
    sp = serial.Serial(port=dev, baudrate=9600, timeout=1,
                       bytesize=8, parity="N", stopbits=1, write_timeout=8)
    try:
        print("\n=== 每次尝试前重发握手 ===")
        for name, start, dlen in VARIANTS:
            r0 = hs(sp)
            if not r0:
                print("  握手失败，设备已退出")
                break
            hdr = module_head(name, dlen, start_addr=start)
            sp.reset_input_buffer()
            sp.write(cmd_head(hdr))
            sp.flush()
            r = rd(sp, 2.5)
            if not r:
                print("  %-9s start=0x%08X len=0x%08X  ★★★ 无 ACK —— 通过！！！" % (name, start, dlen))
                print("  包头: %s" % hdr.hex())
                return 0
            code = r[1] if len(r) > 1 else -1
            print("  %-9s start=0x%08X len=0x%08X  ACK码=0x%02X" % (name, start, dlen, code))
        print("\n全部被拒（或状态无法重置）")
    finally:
        try:
            sp.close()
        except Exception:
            pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
