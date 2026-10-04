#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
荣耀X10 鸿蒙 2.0 → EMUI 10.1.1  USB升级模式 完整刷机脚本
协议：HDLC over CDC-ACM (DBAdapter Reserved Interface)
"""
import sys
import os
import time
import zlib
import struct
import serial
import serial.tools.list_ports

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass


# ---------------- HDLC ----------------
def crc16_x25(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def escape(d):
    out = bytearray()
    for b in d:
        if b in (0x7E, 0x7D):
            out += bytes([0x7D, b ^ 0x20])
        else:
            out.append(b)
    return bytes(out)


def frame(payload):
    return b"\x7e" + escape(payload + crc16_x25(payload).to_bytes(2, "little")) + b"\x7e"


# ---------------- 协议命令 ----------------
MAGIC = 0xA55AAA55


def module_head(name, data_len, hw=b"HW7x27\xff\xff", date=b"2021.08.27",
                tm=b"14.21.49", head_len=100, flags=0xFFFFFFF0,
                start_addr=0xFE000000, block_size=0x0010, block_size_hw=0x0000):
    """
    构造 module_head —— 100 字节
    字段偏移（从 cmd_unit_write_begin_func 反汇编 + UPDATE.APP 实测确认）：
      0x00 dwMagicNum       = 0xA55AAA55
      0x04 headLen          = 100
      0x08 version          = 1
      0x0c hw id            = "HW7x27\\xff\\xff"
      0x14 dwDataStartAddr
      0x18 dwDataLen
      0x1c date  "2021.08.27"
      0x2c time  "14.21.49"
      0x3c module name
      0x5e dwBlockSize      = 0x0010 (大端！)
      0x60 dwBlockSize_hw   = 0x0000 (大端)
    """
    h = bytearray(head_len)
    struct.pack_into("<I", h, 0x00, MAGIC)
    struct.pack_into("<I", h, 0x04, head_len)
    struct.pack_into("<I", h, 0x08, 1)
    h[0x0C:0x0C + len(hw)] = hw[:8]
    struct.pack_into("<I", h, 0x14, start_addr)
    struct.pack_into("<I", h, 0x18, data_len)
    h[0x1C:0x1C + len(date)] = date[:16]
    h[0x2C:0x2C + len(tm)] = tm[:16]
    nm = name.encode() if isinstance(name, str) else name
    h[0x3C:0x3C + len(nm)] = nm
    struct.pack_into(">H", h, 0x5E, block_size)      # ★ 大端
    struct.pack_into(">H", h, 0x60, block_size_hw)   # ★ 大端
    return bytes(h)


def cmd_handshake():
    """★ 新协议握手：命令字 0x0226（字节 26 02），魔数 0x0600A725 在【偏移 2】
    依据：handshake_cmd 反汇编
        bfi  w22, w26, #8, #8      ; cmd = pkt[0] | (pkt[1]<<8)
        cmp  w22, #0x226           ; 只接受 0x0226
        ldur w23, [x19, #2]        ; 魔数在偏移 2
        cmp  w23, 0x0600A725
    """
    c = bytes([0x26, 0x02, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 10 + b"\x00\x01"
    return frame(c)


def cmd_handshake_old():
    """老协议握手（仅作对照）"""
    c = bytes([0x26, 0x00, 0x00, 0x25, 0xA7, 0x00, 0x06]) + b"\x00" * 11 + b"\x01\x00"
    return frame(c)


def cmd_head(header):
    return frame(b"\x41" + header)


def cmd_data(chunk, fileseq, addr):
    p = b"\x0f" + struct.pack(">I", fileseq + addr) + struct.pack(">I", len(chunk)) \
        + zlib.compress(chunk, 1)
    return frame(p)


def cmd_tail(header):
    return frame(b"\x43" + header)


def cmd_reboot():
    return frame(b"\x0a")


def cmd_force_reboot():
    return frame(b"\x32")


# ---------------- 串口 ----------------
def find_port():
    for p in serial.tools.list_ports.comports():
        if "DBAdapter Reserved Interface" in (p.description or ""):
            return p.device
    return None


def rd(sp, secs=2.0):
    t0 = time.time()
    buf = b""
    while time.time() - t0 < secs:
        c = sp.read(4096)
        if c:
            buf += c
            if buf.endswith(b"\x7e") and len(buf) > 4:
                break
    return buf


def main():
    if len(sys.argv) < 2:
        print("用法: flash.py <包文件> [模块名]")
        print("  例: flash.py D:\\base_new2.zip update_sd_base.zip")
        return 2
    path = sys.argv[1]
    modname = sys.argv[2] if len(sys.argv) > 2 else os.path.basename(path)
    if not os.path.exists(path):
        print("找不到文件: %s" % path)
        return 2
    size = os.path.getsize(path)
    print("包文件 : %s" % path)
    print("大小   : %d 字节 (%.2f MB)" % (size, size / 1048576.0))
    print("模块名 : %s" % modname)

    dev = find_port()
    if not dev:
        print("\n❌ 找不到 DBAdapter Reserved Interface —— 手机没在 USB升级模式")
        return 1
    print("端口   : %s" % dev)

    sp = serial.Serial(port=dev, baudrate=9600, timeout=1,
                       bytesize=8, parity="N", stopbits=1, write_timeout=10)
    try:
        # 1) 握手
        print("\n[1/5] 握手 ...")
        sp.reset_input_buffer()
        sp.write(cmd_handshake())
        sp.flush()
        r = rd(sp, 3)
        if not r:
            print("      ❌ 握手无响应")
            return 1
        print("      ✅ 握手成功 (%d 字节)" % len(r))

        # 2) 包头
        print("\n[2/5] 发送包头 (0x41) ...")
        hdr = module_head(modname, size)
        print("      包头: %s" % hdr[:8].hex())
        print("      模块名@0x3c: %r" % hdr[0x3C:0x3C + 32].split(b"\x00")[0])
        sp.write(cmd_head(hdr))
        sp.flush()
        r = rd(sp, 3)
        print("      响应: %s" % (r.hex() if r else "(无)"))

        # 3) 数据
        print("\n[3/5] 发送数据 (0x0F) ...")
        BLK = 0x200000
        seq = 0
        sent = 0
        with open(path, "rb") as f:
            while True:
                chunk = f.read(BLK)
                if not chunk:
                    break
                sp.write(cmd_data(chunk, seq, 0))
                sp.flush()
                sent += len(chunk)
                seq += 1
                pct = sent * 100.0 / size
                print("      %6.2f%%  %d/%d  (%d 块)" % (pct, sent, size, seq))
                rr = rd(sp, 1.0)
                if rr:
                    print("         ← 响应: %s" % rr.hex()[:120])

        # 4) 包尾
        print("\n[4/5] 发送包尾 (0x43) ...")
        sp.write(cmd_tail(hdr))
        sp.flush()
        r = rd(sp, 5)
        print("      响应: %s" % (r.hex() if r else "(无)"))

        # 5) 结束
        print("\n[5/5] 发送结束 ...")
        sp.write(cmd_reboot())
        sp.flush()
        time.sleep(1)
        r = rd(sp, 3)
        print("      响应: %s" % (r.hex() if r else "(无)"))
        print("\n完成。观察手机屏幕。")
    finally:
        try:
            sp.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
