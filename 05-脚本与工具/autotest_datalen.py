#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""守候设备 → 抓到后运行 dwDataLen 递减测试（单进程，避免端口冲突）"""
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

LOG = r"C:\hx10_research\autopush.log"

VARIANTS = [
    ("OTA_ZIP", 0xBA000000, 0x04800000),
    ("OTA_ZIP", 0xBA000000, 0x00800000),
    ("OTA_ZIP", 0xBA000000, 0x00400000),
    ("OTA_ZIP", 0xBA000000, 0x00100000),
    ("OTA_ZIP", 0xBA000000, 0x00040000),
    ("OTA_ZIP", 0xBA000000, 0x00001000),
    ("OTA_ZIP", 0xBA000000, 0x00000000),
    ("OTA_ZIP", 0x00000000, 0x00001000),
    ("OTA_ZIP", 0x00000000, 0x00400000),
]


def P(*a):
    line = " ".join(str(x) for x in a)
    print(line)
    sys.stdout.flush()
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), line))
    except Exception:
        pass


def main():
    P("=" * 62)
    P("守候启动（dwDataLen 上限测试）")
    P("=" * 62)
    deadline = time.time() + 900
    while time.time() < deadline:
        dev = find_port()
        if not dev:
            time.sleep(1.5)
            continue
        try:
            sp = serial.Serial(port=dev, baudrate=9600, timeout=1,
                               bytesize=8, parity="N", stopbits=1, write_timeout=8)
        except Exception:
            time.sleep(1.0)
            continue
        try:
            sp.reset_input_buffer()
            sp.write(cmd_handshake())
            sp.flush()
            r = rd(sp, 1.5)
            if not r:
                continue
            P("")
            P("★★★ 抓到设备 %s  握手 %s" % (dev, r.hex()))
            for name, start, dlen in VARIANTS:
                hdr = module_head(name, dlen, start_addr=start)
                sp.reset_input_buffer()
                sp.write(cmd_head(hdr))
                sp.flush()
                rr = rd(sp, 2.5)
                if not rr:
                    P("  %-10s start=0x%08X len=0x%08X  ★★★ 无 ACK —— 通过！！！" % (name, start, dlen))
                    P("  包头: %s" % hdr.hex())
                    return 0
                code = rr[1] if len(rr) > 1 else -1
                P("  %-10s start=0x%08X len=0x%08X  ACK码=0x%02X" % (name, start, dlen, code))
                sp.write(cmd_tail(hdr))
                sp.flush()
                rd(sp, 1.2)
            P("全部被拒")
            return 1
        except Exception as e:
            P("异常: %s" % e)
        finally:
            try:
                sp.close()
            except Exception:
                pass
        time.sleep(1.5)
    P("❌ 超时")
    return 1


if __name__ == "__main__":
    sys.exit(main())
