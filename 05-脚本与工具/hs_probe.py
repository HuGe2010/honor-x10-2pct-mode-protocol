#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
在华为 5% USB升级模式 的 COM 口上发送 HDLC 握手帧（多端口、多波特率、带重试）
"""
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


def hs_old():
    return frame(bytes([0x26, 0x00, 0x00, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 11 + b"\x01\x00")


def hs_new():
    return frame(bytes([0x26, 0x02, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 10 + b"\x00\x01")


def main():
    print("=== COM 口列表 ===")
    ports = []
    for p in serial.tools.list_ports.comports():
        print("  %-6s  %s" % (p.device, p.description))
        ports.append((p.device, p.description or ""))

    # 优先 DBAdapter，其次其它华为口
    order = sorted(ports, key=lambda x: 0 if "DBAdapter" in x[1] else 1)

    for dev, desc in order:
        for baud in (9600, 115200, 57600, 38400):
            for attempt in range(2):
                try:
                    sp = serial.Serial(port=dev, baudrate=baud, timeout=6,
                                       bytesize=8, parity="N", stopbits=1,
                                       write_timeout=3)
                except Exception as e:
                    print("  [%s@%d] 打开失败: %s" % (dev, baud, e))
                    break
                try:
                    for label, f in (("OLD", hs_old()), ("NEW", hs_new())):
                        sp.reset_input_buffer()
                        sp.reset_output_buffer()
                        time.sleep(0.2)
                        sp.write(f)
                        sp.flush()
                        time.sleep(1.5)
                        r = sp.read(2048)
                        tag = "★ 有响应" if r else "无响应"
                        print("  [%s@%d #%d %s] %s  -> %d 字节 %s" % (
                            dev, baud, attempt + 1, label, tag, len(r),
                            r.hex() if r else ""))
                        if r:
                            sp.close()
                            print("\n★★★ 收到数据！端口=%s 波特率=%d 帧=%s" % (dev, baud, label))
                            return 0
                except Exception as e:
                    print("  [%s@%d] 异常: %s" % (dev, baud, e))
                finally:
                    try:
                        sp.close()
                    except Exception:
                        pass

    print("\n❌ 所有端口/波特率都无响应")
    return 1


if __name__ == "__main__":
    sys.exit(main())
