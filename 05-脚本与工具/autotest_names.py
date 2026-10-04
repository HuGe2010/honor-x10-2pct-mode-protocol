#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""守候设备 → 抓到后立刻迭代测试模块名"""
import sys
import os
import time
import serial

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass

sys.path.insert(0, r"C:\hx10_research")
from flash import (crc16_x25, escape, frame, module_head, cmd_handshake,
                   cmd_head, cmd_tail, find_port, rd)

LOG = r"C:\hx10_research\autopush.log"


def P(*a):
    line = " ".join(str(x) for x in a)
    print(line)
    sys.stdout.flush()
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), line))
    except Exception:
        pass


CANDIDATES = [
    ("OTA_ZIP",      0xBA000000),
    ("OTA_ZIP",      0x00000000),
    ("OTA_ZIP_APP",  0xBA000000),
    ("USERDATA_ZIP", 0x00000000),
    ("BASE_VER",     0xFFFFFFF0),
    ("CUST",         0x70000000),
    ("SYSTEM",       0x00000000),
    ("USERDATA",     0x30000000),
    ("OTA_ZIP",      0x04800000),
    ("OTA_ZIP",      0x00000100),
]

ZIP = r"D:\base_new2.zip"


def main():
    size = os.path.getsize(ZIP)
    P("=" * 62)
    P("守候启动（模块名迭代测试）  包=%s (%d 字节)" % (ZIP, size))
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
            P("★★★ 抓到设备！端口=%s  握手响应 %d 字节: %s" % (dev, len(r), r.hex()))
            # 迭代模块名
            for name, start in CANDIDATES:
                hdr = module_head(name, size, start_addr=start)
                P("--- 模块名=%-14r startAddr=0x%08X ..." % (name, start))
                sp.reset_input_buffer()
                sp.write(cmd_head(hdr))
                sp.flush()
                rr = rd(sp, 2.5)
                if not rr:
                    P("    ★★★ 无 ACK —— 包头【被接受】！！！")
                    P("    正确模块名 = %r   startAddr = 0x%08X" % (name, start))
                    P("    包头 hex = %s" % hdr.hex())
                    return 0
                P("    ACK %s → 被拒绝" % rr.hex())
            P("所有候选都被拒绝")
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
