#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
决定性测试 v2：进 erecovery，高速轮询 COM 口。
若出现新 COM 口，立刻打开并发送 HDLC 握手帧。
"""
import sys
import time
import glob
import subprocess

import usb.core
import usb.backend.libusb1 as b1


def get_backend():
    for pat in [
        r"C:\Program Files\Python*\Lib\site-packages\libusb\_platform\windows\x86_64\libusb-1.0.dll",
    ]:
        for c in glob.glob(pat):
            be = b1.get_backend(find_library=lambda x, p=c: p)
            if be is not None:
                return be
    return b1.get_backend()


BE = get_backend()


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
    c = bytes([0x26, 0x00, 0x00, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 11 + b"\x01\x00"
    return frame(c)


def handshake_new():
    c = bytes([0x26, 0x02, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 10 + b"\x00\x01"
    return frame(c)


def com_ports_detailed():
    """用 PowerShell 拿详细 COM 口信息（含描述）"""
    ps = ("Get-CimInstance Win32_PnPEntity | Where-Object { $_.Name -match 'COM\\d+' } | "
          "ForEach-Object { $_.Name + ' | ' + $_.DeviceID }")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-c", ps],
                           capture_output=True, text=True, timeout=20)
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception as e:
        return ["<查询失败: %s>" % e]


def main():
    # 记录基线
    before = com_ports_detailed()
    print("=== 基线 COM 口 ===")
    for b in before:
        print("  " + b)

    # 进 erecovery
    fb = None
    for d in usb.core.find(find_all=True, backend=BE):
        if d.idVendor == 0x18D1 and d.idProduct == 0xD00D:
            fb = d
            break
    if fb is None:
        print("\nNO_FASTBOOT: 请先把手机弄进 fastboot 模式")
        return 1
    print("\n找到 fastboot，发送 reboot:erecovery ...")
    try:
        fb.set_configuration()
        fb.claim_interface(fb, 0)
        fb.write(0x01, b"reboot:erecovery", timeout=3000)
        try:
            print("  响应:", bytes(fb.read(0x81, 64, timeout=3000)))
        except Exception:
            pass
    except Exception as e:
        print("  发送失败:", e)

    # 高速轮询 COM 口
    print("\n=== 轮询 COM 口（每 2 秒，共 70 秒）===")
    t0 = time.time()
    found = None
    while time.time() - t0 < 70:
        now = com_ports_detailed()
        new = [x for x in now if x not in before]
        el = time.time() - t0
        if new:
            print("  [%.1fs] ★★★ 新增 COM 口！" % el)
            for n in new:
                print("      " + n)
            found = new
            break
        if int(el) % 10 == 0:
            print("  [%.0fs] 当前: %s" % (el, " | ".join(now) if now else "(无)"))
        time.sleep(2)

    if not found:
        print("\n❌ 70 秒内没有新 COM 口出现")
        return 2

    # 尝试打开并握手
    import serial
    portname = found[0].split("|")[0].strip()
    if "(" in portname:
        portname = portname.split("(")[0].strip()
    print("\n=== 尝试打开 %s ===" % portname)
    for baud in (9600, 115200):
        try:
            sp = serial.Serial(port=portname, baudrate=baud, timeout=3)
            print("  ✅ 打开成功 @%d" % baud)
            for name, f in [("老协议", handshake_old()), ("新协议", handshake_new())]:
                print("  --- 发送%s握手: %s" % (name, f.hex()))
                sp.write(f)
                time.sleep(0.5)
                r = sp.read(512)
                print("      收到 %d 字节: %s" % (len(r), r.hex() if r else "(无)"))
            sp.close()
            break
        except Exception as e:
            print("  ❌ @%d 失败: %s" % (baud, e))
    return 0


if __name__ == "__main__":
    sys.exit(main())
