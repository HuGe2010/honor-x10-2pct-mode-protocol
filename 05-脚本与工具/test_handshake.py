#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
决定性测试：在 erecovery 窗口内反复尝试 claim intf0，
成功则发送 HDLC 握手帧并读取响应。
"""
import sys
import time
import glob

import usb.core
import usb.util
import usb.backend.libusb1 as b1


def get_backend():
    for pat in [
        r"C:\Program Files\Python*\Lib\site-packages\libusb\_platform\windows\x86_64\libusb-1.0.dll",
        r"C:\Program Files (x86)\Python*\Lib\site-packages\libusb\_platform\windows\x86_64\libusb-1.0.dll",
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


def crc_bytes(d):
    return crc16_x25(d).to_bytes(2, "little")


def escape(d):
    out = bytearray()
    for b in d:
        if b in (0x7E, 0x7D):
            out += bytes([0x7D, b ^ 0x20])
        else:
            out.append(b)
    return bytes(out)


def frame(payload):
    return b"\x7e" + escape(payload + crc_bytes(payload)) + b"\x7e"


def handshake_old():
    """老协议 usbdload.py 的握手包"""
    c = bytes([0x26, 0x00, 0x00, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 11 + b"\x01\x00"
    return frame(c)


def handshake_new():
    """新协议: cmd=0x0226, magic 紧跟其后"""
    c = bytes([0x26, 0x02, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 10 + b"\x00\x01"
    return frame(c)


def find_erecovery():
    """找 12d1:107e 的 vendor 接口 (0xFF/0xFF)"""
    for d in usb.core.find(find_all=True, backend=BE):
        if d.idVendor != 0x12D1:
            continue
        try:
            for cfg in d:
                for intf in cfg:
                    if intf.bInterfaceClass == 0xFF and intf.bInterfaceSubClass == 0xFF:
                        return d, cfg, intf
        except Exception:
            continue
    return None, None, None


def main():
    # 1) 让手机进 erecovery
    fb = None
    for d in usb.core.find(find_all=True, backend=BE):
        if d.idVendor == 0x18D1 and d.idProduct == 0xD00D:
            fb = d
            break
    if fb is None:
        print("NO_FASTBOOT: 请先把手机弄进 fastboot")
        return 1
    print("找到 fastboot，发送 reboot:erecovery ...")
    try:
        fb.set_configuration()
        usb.util.claim_interface(fb, 0)
        fb.write(0x01, b"reboot:erecovery", timeout=3000)
        try:
            print("  响应:", bytes(fb.read(0x81, 64, timeout=3000)))
        except Exception:
            pass
    except Exception as e:
        print("  发送失败:", e)

    # 2) 在整个窗口内反复尝试
    print("\n=== 轮询 + 尝试 claim（每 1.5 秒，共 60 秒）===")
    t0 = time.time()
    claimed = None
    attempt = 0
    while time.time() - t0 < 60:
        d, cfg, intf = find_erecovery()
        if d is not None:
            attempt += 1
            el = time.time() - t0
            # 列出端点
            eps = [(hex(ep.bEndpointAddress),
                    "IN" if usb.util.endpoint_direction(ep.bEndpointAddress) else "OUT")
                   for ep in intf]
            print("  [%.1fs] 尝试#%d 找到设备 vid=0x%04x pid=0x%04x intf%d EP=%s" % (
                el, attempt, d.idVendor, d.idProduct, intf.bInterfaceNumber, eps))
            try:
                try:
                    d.set_configuration(cfg.bConfigurationValue)
                except Exception as e:
                    print("       set_configuration: %s" % e)
                usb.util.claim_interface(d, intf.bInterfaceNumber)
                print("       ★★★ claim 成功！！！")
                claimed = (d, cfg, intf)
                break
            except Exception as e:
                print("       claim 失败: %s" % e)
        time.sleep(1.5)

    if claimed is None:
        print("\n❌ 60 秒内始终无法 claim 接口")
        return 2

    # 3) 发送握手
    d, cfg, intf = claimed
    ep_in = ep_out = None
    for ep in intf:
        if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT:
            if ep_out is None:
                ep_out = ep.bEndpointAddress
        else:
            if ep_in is None:
                ep_in = ep.bEndpointAddress
    print("\nEP IN=0x%02x OUT=0x%02x" % (ep_in or 0, ep_out or 0))

    for name, f in [("老协议握手", handshake_old()), ("新协议握手", handshake_new())]:
        print("\n--- 发送 %s (%d 字节): %s" % (name, len(f), f.hex()))
        try:
            d.write(ep_out, f, timeout=3000)
            print("    写入成功，等待响应...")
            for _ in range(3):
                try:
                    r = d.read(ep_in, 512, timeout=2000)
                    print("    ✅ 收到 %d 字节: %s" % (len(r), bytes(r).hex()))
                    break
                except Exception as e:
                    print("    读取: %s" % e)
        except Exception as e:
            print("    ❌ 写入失败: %s" % e)
        time.sleep(1)

    try:
        usb.util.release_interface(d, intf.bInterfaceNumber)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
