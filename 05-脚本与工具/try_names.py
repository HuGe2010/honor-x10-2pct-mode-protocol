#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
★ 模块名迭代测试：在一个会话里依次尝试多个候选模块名，
  看哪个【不被拒绝】（无 ACK = 成功）。
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
from flash import (crc16_x25, escape, frame, module_head, cmd_handshake,
                   cmd_head, cmd_tail, find_port, rd)

# 候选模块名（按可能性排序）
CANDIDATES = [
    ("OTA_ZIP",     0xBA000000),
    ("OTA_ZIP",     0x00000000),
    ("OTA_ZIP_APP", 0xBA000000),
    ("USERDATA_ZIP", 0x00000000),
    ("BASE_VER",    0xFFFFFFF0),
    ("CUST",        0x70000000),
    ("SYSTEM",      0x00000000),
    ("USERDATA",    0x30000000),
    ("OTA_ZIP",     0x04800000),
]

ZIP = r"D:\base_new2.zip"


def main():
    dev = find_port()
    if not dev:
        print("❌ 手机不在升级模式")
        return 1
    size = os.path.getsize(ZIP)
    print("端口: %s   包大小: %d" % (dev, size))

    sp = serial.Serial(port=dev, baudrate=9600, timeout=1,
                       bytesize=8, parity="N", stopbits=1, write_timeout=8)
    try:
        print("\n[0] 握手 ...")
        sp.reset_input_buffer()
        sp.write(cmd_handshake())
        sp.flush()
        r = rd(sp, 3)
        print("    -> %s" % (r.hex() if r else "❌ 无响应"))
        if not r:
            return 1

        print("\n=== 依次尝试模块名 ===")
        for name, start in CANDIDATES:
            hdr = module_head(name, size, start_addr=start)
            print("\n--- 模块名=%r  dwDataStartAddr=0x%08X ---" % (name, start))
            sp.reset_input_buffer()
            sp.write(cmd_head(hdr))
            sp.flush()
            r = rd(sp, 2.5)
            if not r:
                print("    ★★★ 无 ACK —— 包头【被接受】！这就是对的模块名！")
                print("    包头: %s" % hdr.hex())
                return 0
            print("    ACK: %s  → 被拒绝" % r.hex())
        print("\n所有候选都被拒绝")
    finally:
        try:
            sp.close()
        except Exception:
            pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
