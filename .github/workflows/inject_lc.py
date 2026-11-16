#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
inject_lc.py — 把 dylib 注入 .ipa/.tipa（纯 Python，不依赖 insert_dylib / optool）

做的事：
  1. 解包
  2. 把 dylib 复制到 Payload/<App>.app/<dylib_name>
  3. 在主二进制头部空闲区插入 LC_LOAD_DYLIB（或 LC_LOAD_WEAK_DYLIB）
  4. 重新打包（保留原条目顺序）

用法：
  python inject_lc.py --ipa 输入.tipa --dylib DFGate.dylib --out 输出.tipa
                      [--weak] [--dylib-path @executable_path/DFGate.dylib]
"""
import argparse, os, shutil, struct, sys, zipfile

LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_SEGMENT_64 = 0x19


def parse_macho(b):
    if struct.unpack("<I", b[:4])[0] != 0xFEEDFACF:
        raise SystemExit("不是 64 位小端 Mach-O")
    ncmds, sizeofcmds = struct.unpack("<II", b[16:24])
    p, first_data = 32, None
    for _ in range(ncmds):
        cmd, size = struct.unpack("<II", b[p:p+8])
        if size <= 0:
            raise SystemExit("load command 异常")
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack("<I", b[p+64:p+68])[0]
            sp = p + 72
            for _ in range(nsects):
                off = struct.unpack("<I", b[sp+48:sp+52])[0]
                if off > 32 and (first_data is None or off < first_data):
                    first_data = off
                sp += 80
        p += size
    return ncmds, sizeofcmds, (first_data or 0x4000)


def make_lc(cmd, path):
    raw = path.encode() + b"\x00"
    size = (24 + len(raw) + 7) & ~7
    buf = bytearray(size)
    struct.pack_into("<III", buf, 0, cmd, size, 24)
    struct.pack_into("<III", buf, 12, 2, 0x10000, 0x10000)
    buf[24:24 + len(raw)] = raw
    return bytes(buf)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa", required=True)
    ap.add_argument("--dylib", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dylib-path", default=None, help="默认 @executable_path/<文件名>")
    ap.add_argument("--weak", action="store_true", help="用 LC_LOAD_WEAK_DYLIB")
    ap.add_argument("--raw-dylib", action="store_true", help="使用 LC_ID_DYLIB 里的 install_name 而非自定义路径")
    a = ap.parse_args()

    dylib_bytes = open(a.dylib, "rb").read()
    if dylib_bytes[:4] not in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        print("  !! 警告：dylib 不是 Mach-O（magic=%s）" % dylib_bytes[:4].hex())

    # 从 dylib 的 LC_ID_DYLIB 读 install_name
    install_name = None
    if a.raw_dylib:
        if struct.unpack("<I", dylib_bytes[:4])[0] == 0xFEEDFACF:
            n = struct.unpack("<I", dylib_bytes[16:20])[0]
            p = 32
            for _ in range(n):
                c, s = struct.unpack("<II", dylib_bytes[p:p+8])
                if c == 0xD:
                    no = struct.unpack("<I", dylib_bytes[p+8:p+12])[0]
                    install_name = dylib_bytes[p+no:p+s].split(b"\x00")[0].decode()
                    break
                p += s
    lc_path = a.dylib_path or install_name or ("@executable_path/" + os.path.basename(a.dylib))

    tmp = os.path.join(os.path.dirname(os.path.abspath(a.out)) or ".", "_inject_tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    z = zipfile.ZipFile(a.ipa)
    names = [n for n in z.namelist() if not n.endswith("/")]
    z.extractall(tmp)

    appdir = None
    for n in names:
        if n.startswith("Payload/") and n.endswith(".app/Info.plist"):
            appdir = n[:-len("Info.plist")]
            break
    if not appdir:
        raise SystemExit("找不到 Payload/*.app")
    app_path = os.path.join(tmp, *appdir.split("/"))

    exe = None
    for f in os.listdir(app_path):
        full = os.path.join(app_path, f)
        if os.path.isfile(full) and "." not in f:
            with open(full, "rb") as fh:
                if fh.read(4) == b"\xcf\xfa\xed\xfe":
                    exe = full
                    break
    if not exe:
        raise SystemExit("找不到主可执行文件")

    # 1) 放 dylib
    dylib_dst = os.path.join(app_path, os.path.basename(a.dylib))
    shutil.copy2(a.dylib, dylib_dst)

    # 2) 注入 LC
    b = bytearray(open(exe, "rb").read())
    ncmds, sizeofcmds, limit = parse_macho(bytes(b))
    lc = make_lc(LC_LOAD_WEAK_DYLIB if a.weak else LC_LOAD_DYLIB, lc_path)
    need = 32 + sizeofcmds + len(lc)
    if need > limit:
        raise SystemExit("头部空间不足：需要 %d，可用 %d" % (need, limit))
    b[32+sizeofcmds:32+sizeofcmds+len(lc)] = lc
    struct.pack_into("<I", b, 16, ncmds + 1)
    struct.pack_into("<I", b, 20, sizeofcmds + len(lc))
    open(exe, "wb").write(b)

    print("  dylib      : %s (%.2f MB)" % (os.path.basename(a.dylib), len(dylib_bytes)/1048576))
    print("  LC 类型    : %s" % ("WEAK_DYLIB" if a.weak else "DYLIB"))
    print("  加载路径   : %s" % lc_path)
    print("  ncmds      : %d -> %d   sizeofcmds: %d -> %d" % (ncmds, ncmds+1, sizeofcmds, sizeofcmds+len(lc)))

    out = os.path.abspath(a.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for n in names:
            p = os.path.join(tmp, *n.split("/"))
            if os.path.exists(p):
                zo.write(p, n)
        zo.write(dylib_dst, appdir + os.path.basename(a.dylib))
    shutil.rmtree(tmp, ignore_errors=True)
    print("  -> %s (%.1f MB)" % (out, os.path.getsize(out)/1048576))


if __name__ == "__main__":
    main()
