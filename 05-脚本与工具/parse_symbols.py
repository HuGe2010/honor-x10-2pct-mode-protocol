#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""手动解析迷你 ELF 的 .symtab / .strtab（绕过段名表截断问题）"""
import sys
import struct
import os

sys.path.insert(0, r"C:\Program Files\Python312\Lib\site-packages")
from elftools.elf.elffile import ELFFile

OUT = r"C:\hx10_research\reports"


def parse_mini_elf(path, tag):
    with open(path, "rb") as f:
        data = f.read()
    elf = ELFFile(open(path, "rb"))

    sym_sec = str_sec = None
    for s in elf.iter_sections():
        if s["sh_type"] == "SHT_SYMTAB":
            sym_sec = s
        elif s["sh_type"] == "SHT_STRTAB" and s.name == ".strtab":
            str_sec = s
    if sym_sec is None:
        # 退而求其次：取第一个 STRTAB 作为 strtab
        for s in elf.iter_sections():
            if s["sh_type"] == "SHT_STRTAB":
                str_sec = s
                break
    if sym_sec is None or str_sec is None:
        print("  [%s] 找不到 symtab/strtab" % tag)
        return []

    soff = sym_sec["sh_offset"]
    ssize = sym_sec["sh_size"]
    stroff = str_sec["sh_offset"]
    strsize = str_sec["sh_size"]
    strtab = data[stroff:stroff + strsize]

    def getstr(off):
        if off >= len(strtab):
            return ""
        end = strtab.find(b"\x00", off)
        if end < 0:
            end = len(strtab)
        return strtab[off:end].decode("utf-8", errors="replace")

    syms = []
    n = ssize // 24
    for i in range(n):
        base = soff + i * 24
        if base + 24 > len(data):
            break
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", data, base)
        nm = getstr(st_name)
        typ = st_info & 0xF
        bind = st_info >> 4
        syms.append({
            "idx": i, "name": nm, "value": st_value, "size": st_size,
            "type": typ, "bind": bind, "shndx": st_shndx,
        })

    symfile = os.path.join(OUT, "symbols-%s.txt" % tag)
    with open(symfile, "w", encoding="utf-8") as f:
        f.write("# idx  value             size    type bind shndx  name\n")
        for s in syms:
            f.write("%6d  0x%016x %8d  %2d  %2d  %5d  %s\n" % (
                s["idx"], s["value"], s["size"], s["type"],
                s["bind"], s["shndx"], s["name"]))
    print("  [%s] 解析出 %d 个符号 -> %s" % (tag, len(syms), symfile))
    return syms


def main():
    all_syms = {}
    for tag, path in [
        ("ours", os.path.join(OUT, "debugdata-ours.elf")),
        ("repo", os.path.join(OUT, "debugdata-repo.elf")),
    ]:
        if not os.path.exists(path):
            print("  缺文件:", path)
            continue
        print("\n########## %s ##########" % tag)
        syms = parse_mini_elf(path, tag)
        all_syms[tag] = syms

        named = [s for s in syms if s["name"]]
        funcs = [s for s in named if s["type"] == 2 and s["size"] > 0]
        print("    有名符号: %d   函数(有大小): %d" % (len(named), len(funcs)))

        # 按大小排序，找大函数（协议实现通常很大）
        print("\n    --- 最大的 25 个函数 ---")
        for s in sorted(funcs, key=lambda x: -x["size"])[:25]:
            print("      %8d  %s" % (s["size"], s["name"]))

        # 关键字筛选
        kws = ["usb", "dload", "update", "hdlc", "frame", "protocol", "zip",
               "cmd", "recv", "recv", "send", "write", "read", "pkg", "package",
               "auth", "verif", "crc", "partition", "flash", "img"]
        print("\n    --- 含关键字的符号（前 80）---")
        hits = [s for s in named if any(k in s["name"].lower() for k in kws)]
        print("      命中 %d 个" % len(hits))
        for s in hits[:80]:
            print("      %8d  %s" % (s["size"], s["name"]))

    # 差异对比
    if "ours" in all_syms and "repo" in all_syms:
        a = set(s["name"] for s in all_syms["ours"] if s["name"])
        b = set(s["name"] for s in all_syms["repo"] if s["name"])
        print("\n########## 两份二进制符号差异 ##########")
        print("  共有: %d" % len(a & b))
        print("  仅 ours: %d" % len(a - b))
        print("  仅 repo: %d" % len(b - a))
        only_ours = sorted(a - b)
        if only_ours:
            print("\n  --- 仅 ours 有（前 40）---")
            for n in only_ours[:40]:
                print("    " + n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
