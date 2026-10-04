#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 update-binary 的 .gnu_debugdata 段提取符号表"""
import sys
import lzma
import io
import os

sys.path.insert(0, r"C:\Program Files\Python312\Lib\site-packages")
from elftools.elf.elffile import ELFFile

OUT = r"C:\hx10_research\reports"


def extract_debugdata(path, tag):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(".gnu_debugdata")
        if sec is None:
            print("  [%s] 没有 .gnu_debugdata" % tag)
            return None
        raw = sec.data()
    print("  [%s] .gnu_debugdata 原始 %d 字节" % (tag, len(raw)))

    # 尝试多种解压方式
    data = None
    for name, fn in [
        ("xz", lambda d: lzma.decompress(d, format=lzma.FORMAT_XZ)),
        ("lzma-alone", lambda d: lzma.decompress(d, format=lzma.FORMAT_ALONE)),
        ("raw-lzma", lambda d: lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(d)),
        ("gzip", None),
    ]:
        if fn is None:
            continue
        try:
            data = fn(raw)
            print("  [%s] 解压成功(%s): %d 字节" % (tag, name, len(data)))
            break
        except Exception as e:
            print("  [%s] %s 解压失败: %s" % (tag, name, str(e)[:60]))

    if data is None:
        # 存原始数据供人工分析
        outp = os.path.join(OUT, "debugdata-%s.raw" % tag)
        with open(outp, "wb") as f:
            f.write(raw)
        print("  [%s] 已存原始数据: %s" % (tag, outp))
        return None

    outp = os.path.join(OUT, "debugdata-%s.elf" % tag)
    with open(outp, "wb") as f:
        f.write(data)
    print("  [%s] 已存解压后的 ELF: %s" % (tag, outp))

    # 解析符号
    try:
        inner = ELFFile(io.BytesIO(data))
        print("  [%s] 内部 ELF: %s, 段:" % (tag, inner['e_machine']))
        for s in inner.iter_sections():
            print("      %-20s type=%-14s size=%d" % (s.name, s['sh_type'], s['sh_size']))

        symtab = inner.get_section_by_name(".symtab")
        if symtab is None:
            print("  [%s] 内部没有 .symtab" % tag)
            return data
        syms = list(symtab.iter_symbols())
        print("  [%s] ★ 符号总数: %d" % (tag, len(syms)))

        # 存全部符号
        symfile = os.path.join(OUT, "symbols-%s.txt" % tag)
        with open(symfile, "w", encoding="utf-8") as f:
            for s in syms:
                f.write("0x%016x %6d %-8s %s\n" % (
                    s['st_value'], s['st_size'],
                    s['st_info']['type'], s['name']))
        print("  [%s] 符号表已存: %s" % (tag, symfile))
        return data
    except Exception as e:
        print("  [%s] 内部 ELF 解析失败: %s" % (tag, e))
        return data


def main():
    os.makedirs(OUT, exist_ok=True)
    for tag, path in [
        ("ours", r"C:\hx10_research\binaries\update-binary-ours"),
        ("repo", r"C:\hx10_research\binaries\update-binary-repo"),
    ]:
        print("\n########## %s ##########" % tag)
        extract_debugdata(path, tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
