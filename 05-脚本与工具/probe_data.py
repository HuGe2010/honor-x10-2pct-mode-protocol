#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""趁设备在模式里：握手 → 包头 → 真实数据块 → 看 ACK"""
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
                   cmd_head, cmd_data, cmd_tail, find_port, rd)

ZIP = r"D:\base_new2.zip"


def main():
    dev = find_port()
    if not dev:
        print("❌ 手机不在 USB升级模式")
        return 1
    print("端口: %s" % dev)

    size = os.path.getsize(ZIP) if os.path.exists(ZIP) else 4096
    print("包: %s (%d 字节)" % (ZIP, size))

    sp = serial.Serial(port=dev, baudrate=9600, timeout=1,
                       bytesize=8, parity="N", stopbits=1, write_timeout=10)
    try:
        print("\n[1] 握手 ...")
        sp.reset_input_buffer()
        sp.write(cmd_handshake())
        sp.flush()
        r = rd(sp, 3)
        print("    -> %s" % ("OK %d字节" % len(r) if r else "❌ 无响应"))
        if not r:
            return 1

        hdr = module_head("update_sd_base.zip", size)
        print("\n[2] 包头 0x41 ...")
        sp.write(cmd_head(hdr))
        sp.flush()
        r = rd(sp, 3)
        print("    -> %s" % (r.hex() if r else "(无响应)"))

        print("\n[3] 数据块 0x0F (64KB) ...")
        with open(ZIP, "rb") as f:
            chunk = f.read(65536)
        print("    块大小 %d" % len(chunk))
        sp.write(cmd_data(chunk, 0, 0))
        sp.flush()
        r = rd(sp, 5)
        print("    -> %s" % (r.hex() if r else "(无响应)"))
        if r:
            print("    ★ 设备 ACK 了！协议正确！")

        print("\n[4] 再握手确认设备存活 ...")
        sp.reset_input_buffer()
        sp.write(cmd_handshake())
        sp.flush()
        r = rd(sp, 3)
        print("    -> %s" % ("OK %d字节" % len(r) if r else "❌ 无响应"))

        print("\n[5] 包尾 0x43 ...")
        sp.write(cmd_tail(hdr))
        sp.flush()
        r = rd(sp, 4)
        print("    -> %s" % (r.hex() if r else "(无响应)"))
    finally:
        try:
            sp.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
