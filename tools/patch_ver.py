#!/usr/bin/env python3
"""原地改写 PE 的版本资源（VS_FIXEDFILEINFO + StringFileInfo 文本）。

用途：把 dlssg_for_sm86 的 bundle nvngx_dlssg.dll（310,1,0,0）改成游戏自身那份的版本
（例如 310,5,2,0），让游戏的版本校验通过 —— 不需要运行时钩版本 API。

用法：python patch_ver.py <输入.dll> <输出.dll> <版本字符串，如 310,5,2,0>
"""
import struct, sys, re


def patch(path, out, new_ver_str, ver_ms, ver_ls):
    d = bytearray(open(path, 'rb').read())
    sig = struct.pack('<I', 0xFEEF04BD)
    n_fixed, pos = 0, 0
    while True:
        i = d.find(sig, pos)
        if i < 0:
            break
        struct.pack_into('<I', d, i + 8, ver_ms)
        struct.pack_into('<I', d, i + 12, ver_ls)
        struct.pack_into('<I', d, i + 16, ver_ms)
        struct.pack_into('<I', d, i + 20, ver_ls)
        n_fixed += 1
        pos = i + 4
    unit = rb'(?:[0-9]\\x00)+'
    pat = re.compile(unit + rb',\\x00' + unit + rb',\\x00' + unit + rb',\\x00' + unit)
    found = {}
    for m in pat.finditer(bytes(d)):
        t = m.group().decode('utf-16-le')
        found[t] = found.get(t, 0) + 1
    new_b = new_ver_str.encode('utf-16-le')
    n_str = 0
    for txt, cnt in found.items():
        old_b = txt.encode('utf-16-le')
        if len(old_b) != len(new_b):
            print('  跳过(长度不同): %s (%d处)' % (txt, cnt))
            continue
        d = bytearray(bytes(d).replace(old_b, new_b))
        n_str += cnt
        print('  替换: %s -> %s x%d' % (txt, new_ver_str, cnt))
    open(out, 'wb').write(bytes(d))
    print('VS_FIXEDFILEINFO: %d 处, 字符串替换: %d 处 -> %s' % (n_fixed, n_str, out))


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    a = [int(x) for x in sys.argv[3].split(',')]
    patch(sys.argv[1], sys.argv[2], sys.argv[3], (a[0] << 16) | a[1], (a[2] << 16) | a[3])
