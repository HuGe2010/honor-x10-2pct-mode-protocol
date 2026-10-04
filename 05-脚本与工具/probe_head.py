#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""只测试包头格式：握手 → head(0x41) → tail(0x43)，观察设备响应"""
import sys
import os
import time
import struct
import serial
import serial.tools.list_ports

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass

sys.path.insert(0, r"C:\hx10_research")
from flash import crc16_x25, escape, frame, module_head, cmd_handshake, cmd_head, cmd_tail, find_port, rd


def main():
    modname = sys.argv[1] if len(sys.argv) > 1 else "update_sd_base.zip"
    size = int(sys.argv[2]) if len(sys.argv) > 2 else 100

    dev = find_port()
    if not dev:
        print("❌ 找不到 DBAdapter Reserved Interface —— 手机没在 USB升级模式")
        return 1
    print("端口: %s   模块名: %s   声明长度: %d" % (dev, modname, size))

    sp = serial.Serial(port=dev, baudrate=9600, timeout=1,
                       bytesize=8, parity="N", stopbits=1, write_timeout=10)
    try:
        print("\n[1] 握手 ...")
        sp.reset_input_buffer()
        sp.write(cmd_handshake())
        sp.flush()
        r = rd(sp, 3)
        print("    -> %s" % (r.hex() if r else "(无响应)"))
        if not r:
            return 1

        print("\n[2] 包头 0x41 ...")
        hdr = module_head(modname, size)
        print("    header(%d字节): %s" % (len(hdr), hdr.hex()))
        print("    魔数   : 0x%08X" % struct.unpack_from("<I", hdr, 0)[0])
        print("    headLen: %d" % struct.unpack_from("<I", hdr, 4)[0])
        print("    硬件   : %r" % hdr[0x0C:0x14])
        print("    dataLen: %d" % struct.unpack_from("<I", hdr, 0x18)[0])
        print("    模块名 : %r" % hdr[0x3C:0x3C+32].split(b"\x00")[0])
        sp.write(cmd_head(hdr))
        sp.flush()
        r = rd(sp, 4)
        print("    -> %s" % (r.hex() if r else "(无响应)"))

        print("\n[3] 包尾 0x43 ...")
        sp.write(cmd_tail(hdr))
        sp.flush()
        r = rd(sp, 4)
        print("    -> %s" % (r.hex() if r else "(无响应)"))

        print("\n完成。")
    finally:
        try:
            sp.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
