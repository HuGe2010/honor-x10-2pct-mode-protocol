#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速握手探测 —— 实时输出，不做缓冲
优先 COM4 (DBAdapter Reserved Interface)
"""
import sys
import time
import serial
import serial.tools.list_ports

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
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


HS_OLD = frame(bytes([0x26, 0x00, 0x00, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 11 + b"\x01\x00")
HS_NEW = frame(bytes([0x26, 0x02, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 10 + b"\x00\x01")


def P(*a):
    print(*a)
    sys.stdout.flush()


def main():
    P("=== COM 口 ===")
    ports = list(serial.tools.list_ports.comports())
    for p in ports:
        P("  %-6s  %s" % (p.device, p.description))
    order = sorted(ports, key=lambda x: 0 if "DBAdapter" in (x.description or "") else 1)

    for p in order:
        dev = p.device
        for baud in (9600, 115200):
            try:
                sp = serial.Serial(port=dev, baudrate=baud, timeout=3,
                                   bytesize=8, parity="N", stopbits=1, write_timeout=3)
            except Exception as e:
                P("  [%s@%d] 打不开: %s" % (dev, baud, e))
                break
            try:
                for label, f in (("OLD", HS_OLD), ("NEW", HS_NEW)):
                    sp.reset_input_buffer()
                    sp.reset_output_buffer()
                    sp.write(f)
                    sp.flush()
                    t0 = time.time()
                    r = b""
                    while time.time() - t0 < 3:
                        chunk = sp.read(256)
                        if chunk:
                            r += chunk
                            if len(r) > 8:
                                break
                    if r:
                        P("\n★★★ 收到响应！ %s @%d  %s  -> %d 字节" % (dev, baud, label, len(r)))
                        P("    HEX: %s" % r.hex())
                        sp.close()
                        return 0
                    P("  [%s@%d %s] 无响应" % (dev, baud, label))
            except Exception as e:
                P("  [%s@%d] 异常: %s" % (dev, baud, e))
            finally:
                try:
                    sp.close()
                except Exception:
                    pass

    P("\n❌ 全部无响应")
    return 1


if __name__ == "__main__":
    sys.exit(main())
