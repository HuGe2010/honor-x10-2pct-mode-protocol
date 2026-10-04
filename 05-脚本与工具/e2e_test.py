#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2% 模式端到端测试：握手 → 包头 → 真实数据块 → 看 ACK
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


def cmd_data_new(chunk, addr, seq_off=0):
    """新协议数据帧：0x0F + 地址(4B BE) + 长度(4B BE) + zlib(data)"""
    import zlib
    p = b"\x0f" + struct.pack(">I", addr + seq_off) + struct.pack(">I", len(chunk)) \
        + zlib.compress(chunk, 1)
    return frame(p)


def main():
    dev = find_port()
    if not dev:
        print("❌ 找不到 DBAdapter Reserved Interface")
        return 1
    size = os.path.getsize(ZIP)
    print("端口: %s   包: %s (%d 字节)" % (dev, ZIP, size))

    sp = serial.Serial(port=dev, baudrate=9600, timeout=1,
                       bytesize=8, parity="N", stopbits=1, write_timeout=8)
    try:
        # 1 握手
        print("\n[1] 握手 ...")
        sp.reset_input_buffer()
        sp.write(cmd_handshake())
        sp.flush()
        r = rd(sp, 3)
        print("    -> %s" % ("OK %d字节" % len(r) if r else "❌ 无响应"))
        if not r:
            return 1

        # 2 包头
        print("\n[2] 包头 0x41 (100字节) ...")
        hdr = module_head("update_sd_base.zip", size, start_addr=0)
        sp.write(cmd_head(hdr))
        sp.flush()
        r = rd(sp, 3)
        print("    -> %s" % (r.hex() if r else "(无响应 = 成功，设备成功时不回 ACK)"))

        # 3 数据块
        BLK = 0x200000
        print("\n[3] 数据 0x0F (%d 字节块) ..." % BLK)
        with open(ZIP, "rb") as f:
            chunk = f.read(BLK)
        f = cmd_data_new(chunk, 0)
        print("    原始 %d 字节 -> 帧 %d 字节" % (len(chunk), len(f)))
        try:
            sp.write(f)
            sp.flush()
            print("    写入完成")
        except Exception as e:
            print("    ❌ 写失败: %s" % e)
        r = rd(sp, 8)
        print("    -> %s" % (r.hex() if r else "(无响应)"))

        # 4 再握手确认存活
        print("\n[4] 再握手确认存活 ...")
        sp.reset_input_buffer()
        sp.write(cmd_handshake())
        sp.flush()
        r = rd(sp, 3)
        print("    -> %s" % ("OK %d字节" % len(r) if r else "❌ 无响应"))

        # 5 包尾
        print("\n[5] 包尾 0x43 ...")
        sp.write(cmd_tail(hdr))
        sp.flush()
        r = rd(sp, 6)
        print("    -> %s" % (r.hex() if r else "(无响应)"))
    finally:
        try:
            sp.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
