#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2% 模式（三键线刷）—— 原生 USB bulk 通信
intf0 (0xFF/0xFF/0x00): EP OUT 0x01 / EP IN 0x81
"""
import sys
import os
import time
import glob
import struct

import usb.core
import usb.util
import usb.backend.libusb1 as b1

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass

sys.path.insert(0, r"C:\hx10_research")
from flash import crc16_x25, escape, frame, module_head, cmd_handshake, cmd_head, cmd_data, cmd_tail


def get_backend():
    for pat in [r"C:\Program Files\Python*\Lib\site-packages\libusb\_platform\windows\x86_64\libusb-1.0.dll"]:
        for c in glob.glob(pat):
            be = b1.get_backend(find_library=lambda x, p=c: p)
            if be:
                return be
    return b1.get_backend()


BE = get_backend()


def find_dev():
    for d in usb.core.find(find_all=True, backend=BE):
        if d.idVendor == 0x12D1 and d.idProduct == 0x107E:
            try:
                for cfg in d:
                    for intf in cfg:
                        if intf.bInterfaceClass == 0xFF and intf.bInterfaceSubClass == 0xFF:
                            return d, cfg, intf
            except Exception:
                continue
    return None, None, None


def main():
    d, cfg, intf = find_dev()
    if d is None:
        print("❌ 没找到 2% 模式设备 (12d1:107e, intf 0xFF/0xFF)")
        return 1
    print("找到设备 bus=%s addr=%s intf%d" % (d.bus, d.address, intf.bInterfaceNumber))

    ep_in = ep_out = None
    for ep in intf:
        if ep.bEndpointAddress & 0x80:
            if ep_in is None:
                ep_in = ep.bEndpointAddress
        else:
            if ep_out is None:
                ep_out = ep.bEndpointAddress
    print("EP IN=0x%02x OUT=0x%02x" % (ep_in, ep_out))

    try:
        d.set_configuration(cfg.bConfigurationValue)
    except Exception as e:
        print("  set_configuration: %s" % e)
    try:
        usb.util.claim_interface(d, intf.bInterfaceNumber)
        print("  ★ claim 成功！")
    except Exception as e:
        print("  ❌ claim 失败: %s" % e)
        return 2

    try:
        # 握手
        print("\n[1] 发送握手帧 ...")
        f = cmd_handshake()
        print("    %s" % f.hex())
        d.write(ep_out, f, timeout=3000)
        for _ in range(5):
            try:
                r = bytes(d.read(ep_in, 4096, timeout=2000))
                print("    ★ 收到 %d 字节: %s" % (len(r), r.hex()[:200]))
                break
            except Exception as e:
                print("    读取: %s" % e)
                break

        # 包头
        print("\n[2] 发送包头 0x41 ...")
        hdr = module_head("update_sd_base.zip", os.path.getsize(r"D:\base_new2.zip"))
        print("    包头 %d 字节" % len(hdr))
        d.write(ep_out, cmd_head(hdr), timeout=3000)
        for _ in range(3):
            try:
                r = bytes(d.read(ep_in, 4096, timeout=2000))
                print("    ← %d 字节: %s" % (len(r), r.hex()[:200]))
                break
            except Exception as e:
                print("    读取: %s" % e)
                break
    finally:
        try:
            usb.util.release_interface(d, intf.bInterfaceNumber)
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
