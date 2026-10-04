#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
★★★ 单次尝试版：抓到设备后【只发一个包头】就结束
    每个会话只有第一次包头尝试有效（之后状态锁死 0x0D）
    用法: autotest_single.py <模块名> <startAddr> <dataLen>
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
from flash import (module_head, cmd_handshake, cmd_head, cmd_tail, find_port, rd)

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


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "OTA_ZIP"
    start = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0
    dlen = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x1000

    P("=" * 62)
    P("单次尝试  模块名=%s start=0x%08X len=0x%08X (%d)" % (name, start, dlen, dlen))
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
            r = rd(sp, 2)
            if not r:
                continue
            P("★★★ 抓到设备  握手=%s" % r.hex())
            hdr = module_head(name, dlen, start_addr=start)
            P("发包头 (%d 字节): %s" % (len(hdr), hdr.hex()))
            sp.reset_input_buffer()
            sp.write(cmd_head(hdr))
            sp.flush()
            rr = rd(sp, 3)
            if not rr:
                P("")
                P("★★★★★★ 无 ACK —— 包头【被接受】！！！")
                P("正确参数: 模块名=%r start=0x%08X len=0x%08X" % (name, start, dlen))
                return 0
            code = rr[1] if len(rr) > 1 else -1
            P("ACK %s  错误码=0x%02X  → 被拒绝" % (rr.hex(), code))
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
