#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 DBAdapter Reserved Interface (COM4) 上发送 HDLC 握手帧"""
import sys
import time
import serial
import serial.tools.list_ports

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def crc16_x25(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def frame(payload):
    d = payload + crc16_x25(payload).to_bytes(2, "little")
    out = bytearray()
    for b in d:
        if b in (0x7E, 0x7D):
            out += bytes([0x7D, b ^ 0x20])
        else:
            out.append(b)
    return b"\x7e" + bytes(out) + b"\x7e"


def handshake_old():
    """usbdload.py 原版"""
    c = bytes([0x26, 0x00, 0x00, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 11 + b"\x01\x00"
    return frame(c)


def handshake_new():
    """新协议: cmd=0x0226, magic 紧跟"""
    c = bytes([0x26, 0x02, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 10 + b"\x00\x01"
    return frame(c)


def main():
    print("=== 当前 COM 口 ===")
    target = None
    for p in serial.tools.list_ports.comports():
        desc = p.description or ""
        vidpid = ("%04X:%04X" % (p.vid, p.pid)) if (p.vid and p.pid) else "n/a"
        print("  %-6s  %-45s  VID:PID=%s" % (p.device, desc, vidpid))
        if "DBAdapter Reserved Interface" in desc:
            target = p.device
    if target is None:
        print("\n❌ 没找到 DBAdapter Reserved Interface")
        return 1
    print("\n★ 目标端口: %s" % target)

    for baud in (9600, 115200):
        try:
            sp = serial.Serial(port=target, baudrate=baud, timeout=3,
                               bytesize=8, parity="N", stopbits=1)
            print("\n=== 打开 %s @ %d ===" % (target, baud))
            for name, f in [("老协议握手", handshake_old()), ("新协议握手", handshake_new())]:
                print("--- %s (%d 字节): %s" % (name, len(f), f.hex()))
                sp.reset_input_buffer()
                sp.write(f)
                sp.flush()
                time.sleep(1.0)
                r = sp.read(1024)
                if r:
                    print("    ✅ 收到 %d 字节: %s" % (len(r), r.hex()))
                    try:
                        print("       文本: %r" % r.decode("utf-8", errors="replace"))
                    except Exception:
                        pass
                else:
                    print("    (无响应)")
            sp.close()
        except Exception as e:
            print("  ❌ @%d 失败: %s" % (baud, e))
    return 0


if __name__ == "__main__":
    sys.exit(main())
