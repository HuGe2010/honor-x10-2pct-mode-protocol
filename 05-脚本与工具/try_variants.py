#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
★ 变体迭代：模块名固定 OTA_ZIP，变化 dwDataLen / startAddr
   每次失败后发包尾(0x43)尝试重置状态
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

ZIP = r"D:\base_new2.zip"
REAL = os.path.getsize(ZIP)

# (模块名, startAddr, dataLen)
VARIANTS = [
    ("OTA_ZIP", 0xBA000000, REAL),
    ("OTA_ZIP", 0xBA000000, 0x10000000),
    ("OTA_ZIP", 0xBA000000, 0x00010000),
    ("OTA_ZIP", 0xBA000000, 0x00000400),
    ("OTA_ZIP", 0x00000000, 0x10000000),
    ("OTA_ZIP", 0x00000000, 0x00010000),
    ("OTA_ZIP_APP", 0xBA000000, REAL),
    ("OTA_ZIP_APP", 0x00000000, 0x10000000),
]


def main():
    dev = find_port()
    if not dev:
        print("❌ 手机不在升级模式")
        return 1
    print("端口 %s   真实包大小 %d" % (dev, REAL))

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

        print("\n=== 变体测试 ===")
        for name, start, dlen in VARIANTS:
            hdr = module_head(name, dlen, start_addr=start)
            print("\n--- %s start=0x%08X len=%d(0x%X) ---" % (name, start, dlen, dlen))
            sp.reset_input_buffer()
            sp.write(cmd_head(hdr))
            sp.flush()
            r = rd(sp, 2.5)
            if not r:
                print("    ★★★ 无 ACK —— 被接受！")
                return 0
            code = r[1] if len(r) > 1 else -1
            print("    ACK %s  错误码=0x%02X" % (r.hex(), code))
            # 发包尾尝试重置
            sp.write(cmd_tail(hdr))
            sp.flush()
            rt = rd(sp, 1.5)
            if rt:
                print("    包尾响应: %s" % rt.hex())
        print("\n全部被拒")
    finally:
        try:
            sp.close()
        except Exception:
            pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
