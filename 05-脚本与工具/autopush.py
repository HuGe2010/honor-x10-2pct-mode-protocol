#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动守候 + 瞬间接管
持续轮询 COM4 发握手；一旦成功，立刻发送包头和数据。
用法: autopush.py [--test] [包文件] [模块名]
  --test : 只发 包头 + 1个数据块 + 包尾（快速验证协议）
"""
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
from flash import (crc16_x25, escape, frame, module_head, cmd_handshake,
                   cmd_head, cmd_data, cmd_tail, cmd_reboot, find_port, rd)

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


def adb_present():
    """正常系统会有 Android Composite ADB Interface (SUBCLASS_42)"""
    import subprocess
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-c",
             "(Get-PnpDevice -PresentOnly -EA SilentlyContinue | "
             "Where-Object { $_.InstanceId -match 'SUBCLASS_42' } | "
             "Measure-Object).Count"],
            capture_output=True, text=True, timeout=15)
        return r.stdout.strip() not in ("0", "")
    except Exception:
        return False


def find_port_ready():
    """直接返回端口 —— 握手本身就能判断设备是否在升级模式。
    注意：升级模式下 ADB 接口【存在】但 adbd 没运行，
    所以不能用接口存在性判断，只能靠握手是否响应。"""
    return find_port()


def try_handshake(sp):
    try:
        sp.reset_input_buffer()
        sp.write(cmd_handshake())
        sp.flush()
        return rd(sp, 1.5)
    except Exception:
        return b""


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    test = "--test" in sys.argv
    path = args[0] if args else r"D:\base_new2.zip"
    modname = args[1] if len(args) > 1 else "update_sd_base.zip"
    size = os.path.getsize(path) if os.path.exists(path) else 0
    P("=" * 60)
    P("自动守候启动  包=%s (%d 字节)  模块名=%s  测试模式=%s" % (path, size, modname, test))
    P("=" * 60)

    dev = find_port()
    if not dev:
        P("❌ 找不到 DBAdapter Reserved Interface（手机还没进模式）")
        P("   等待手机进入 USB升级模式 ...")
    else:
        P("端口 %s 已就绪，开始守候" % dev)

    deadline = time.time() + 900   # 15 分钟
    caught = False
    while time.time() < deadline:
        d = find_port_ready()
        if not d:
            time.sleep(1.5)
            continue
        try:
            sp = serial.Serial(port=d, baudrate=9600, timeout=1,
                               bytesize=8, parity="N", stopbits=1, write_timeout=10)
        except Exception as e:
            time.sleep(1.0)
            continue
        try:
            r = try_handshake(sp)
            if r:
                P("")
                P("★★★ 抓到设备！端口=%s  握手响应 %d 字节" % (d, len(r)))
                caught = True
                run_session(sp, path, modname, size, test)
                break
        finally:
            try:
                sp.close()
            except Exception:
                pass
        time.sleep(1.5)

    if not caught:
        P("❌ 超时未抓到设备")
        return 1
    return 0


def run_session(sp, path, modname, size, test):
    # ★ 测试模式下：包头声明的长度 = 实际要发送的长度，否则设备等不到数据就失败
    BLK = 0x200000 if not test else 0x100000
    if test:
        send_size = min(BLK * 2, size)
    else:
        send_size = size
    hdr = module_head(modname, send_size, start_addr=0)
    P("[包头] 模块名=%r  声明长度=%d  blockSize=0x%04X" % (
        hdr[0x3C:0x3C+40].split(b"\x00")[0], send_size,
        struct.unpack_from(">H", hdr, 0x5E)[0]))

    # 立即发包头
    P("[1] 包头 0x41 ...")
    sp.write(cmd_head(hdr))
    sp.flush()
    r = rd(sp, 2)
    P("    -> %s" % (r.hex() if r else "(无响应 = 成功，设备成功时不回 ACK)"))

    P("[2] 数据 0x0F (块大小 0x%x) ..." % BLK)
    seq = 0
    sent = 0
    t0 = time.time()
    acked = 0
    with open(path, "rb") as f:
        while sent < send_size:
            chunk = f.read(min(BLK, send_size - sent))
            if not chunk:
                break
            try:
                sp.write(cmd_data(chunk, sent, 0))
                sp.flush()
            except Exception as e:
                P("    ❌ 写失败 @%d: %s" % (sent, e))
                break
            sent += len(chunk)
            seq += 1
            rr = rd(sp, 0.3)
            if rr:
                acked += 1
                P("    ★ ACK#%d: %s" % (acked, rr.hex()[:120]))
            el = time.time() - t0
            P("    %6.2f%%  %d/%d  块=%d  ACK=%d  %.1f MB/s" % (
                sent * 100.0 / send_size if send_size else 0, sent, send_size,
                seq, acked, sent / 1048576.0 / el if el > 0 else 0))

    P("[3] 包尾 0x43 ...")
    sp.write(cmd_tail(hdr))
    sp.flush()
    r = rd(sp, 8)
    P("    -> %s" % (r.hex() if r else "(无响应)"))
    P("[4] 总计发送 %d 字节，收到 %d 个 ACK" % (sent, acked))
    P("完成。观察手机屏幕！")


if __name__ == "__main__":
    sys.exit(main())
