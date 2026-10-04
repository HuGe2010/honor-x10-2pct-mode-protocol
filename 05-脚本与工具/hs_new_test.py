#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
★ 只用【新协议握手】(cmd=0x0226, 魔数@偏移2) 测试
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
from flash import crc16_x25, escape, frame, find_port, rd


def hs_new():
    """新协议握手：cmd=0x0226(字节 26 02)，魔数 0x0600A725 在偏移 2"""
    c = bytes([0x26, 0x02, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 10 + b"\x00\x01"
    return frame(c)


def hs_old():
    c = bytes([0x26, 0x00, 0x00, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 11 + b"\x01\x00"
    return frame(c)


def main():
    dev = find_port()
    if not dev:
        print("❌ 手机不在升级模式（找不到 DBAdapter 口）")
        return 1
    print("端口: %s" % dev)

    sp = serial.Serial(port=dev, baudrate=9600, timeout=1,
                       bytesize=8, parity="N", stopbits=1, write_timeout=8)
    try:
        print("\n★★★ 只发【新协议握手】(0x0226) ...")
        f = hs_new()
        print("    帧: %s" % f.hex())
        sp.reset_input_buffer()
        sp.write(f)
        sp.flush()
        r = rd(sp, 5)
        if r:
            print("    ✅ 收到 %d 字节！" % len(r))
            print("    HEX: %s" % r.hex())
            # 解析
            p = r[1:-1] if len(r) > 2 else r
            print("    载荷[0..1] = cmd = 0x%04X" % (p[0] | (p[1] << 8) if len(p) >= 2 else -1))
            if len(p) >= 6:
                import struct
                print("    载荷[2..5] = 0x%08X" % struct.unpack_from("<I", p, 2)[0])
        else:
            print("    ❌ 无响应")

        time.sleep(0.5)
        print("\n--- 对照：老协议握手 (0x0026) ---")
        sp.reset_input_buffer()
        sp.write(hs_old())
        sp.flush()
        r2 = rd(sp, 4)
        print("    -> %s" % (r2.hex() if r2 else "(无响应)"))
    finally:
        try:
            sp.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
