# jadx 卡死时的替代：最小 DEX 解析器 + 字符串表邻接/簇分析（无需反编译）

- **code**: jadx-卡死时的替代-最小-dex-解析器-字符串表邻接-簇分析-无需反编译
- **kind**: script
- **category**: frontend-reverse
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在本战役真机验证：`lz2_carved_0x3092c8.dex` 解析出 **8477 类 / 58853 方法 / 52177 字符串**（与 jadx 报出的量级一致），并据此拿到关键证据 —— ① `--neigh "/login4" 45` 得到 `/login4` 紧邻 `/mac=`（⇒ 登录请求带设备指纹）② `--neigh "getnewyzm"`+`--grep` 定位到登录参数簇 idx 38111~38150（`login4 / loginType / logpswd / loguser / logyzm`，同簇混有 `login_username/login_phone/login_btn/login_lay` 这类布局资源 id）③ 端点常量表 idx 2400~2560（`/login4 /mac= /register18 /user_set /Register_phone`）与 v27 认证子路径 `verification/send|verify|status|cancel`。**对照基准**：同一台机器上 jadx CLI（jadx-1.5.6-all.jar，-Xmx3g）跑 50 分钟仅消耗 2.4 秒 CPU、零产出；本脚本同任务 **< 1 分钟**出结果。
- **path**: pocs/jadx-卡死时的替代-最小-dex-解析器-字符串表邻接-簇分析-无需反编译/dex_strings.py
- **tags**: android,apk,dex,静态分析,jadx替代,字符串邻接,不反编译
- **created_at**: 2026-10-11T19:02:58.811Z
- **found_by**: exploit

## 描述

无需反编译的 APK 静态分析：解析 DEX header/string_ids/type_ids/method_ids/class_defs/code_item，做「字符串表邻接/簇分析」与「const-string 引用分析」。jadx CLI 在本机卡死（50 分钟仅 2.4s CPU、零产出）时用它替代，几分钟出证据。本战役据此挖出 loguser/logpswd/logyzm 簇与 login4/login_2020 端点常量，并做了自我否证。

## 用法

```
# 1) 列出字符串表规模（确认 dex 完整）
python dex_strings.py work/vulnscan/apk2025/lz2_carved_0x3092c8.dex

# 2) ★ 最有用：打印目标串的 ±N 邻居（DEX 串表大致按源码顺序 ⇒ 邻接=同段代码的字面量）
python dex_strings.py work/vulnscan/apk2025/lz2_carved_0x3092c8.dex --neigh "/login4" 45
python dex_strings.py work/vulnscan/apk2025/lz2_carved_0x3092c8.dex --neigh "getnewyzm" 45

# 3) 找引用该串的类/方法，并 dump 该方法引用到的全部字符串（≈ 该函数的字面量清单）
python dex_strings.py work/vulnscan/apk2025/lz2_carved_0x3092c8.dex --refs "/login4"

# 4) 短串正则筛（找参数名/端点名/资源名）
python dex_strings.py work/vulnscan/apk2025/lz2_carved_0x3092c8.dex --grep "yzm|verify|sms" 40

# carve 出的 dex 位置（本战役）：
#   work/vulnscan/apk2025/lz2_carved_0x0.dex        (11805553 B, 壳前段)
#   work/vulnscan/apk2025/lz2_carved_0x25c8.dex     ( 3173588 B)
#   work/vulnscan/apk2025/lz2_carved_0x3092c8.dex   ( 8622108 B, ★ 业务主体 8477 类/58853 方法)
#   work/vulnscan/apk2025/lz2025_carved_0x0.dex     ( 8830584 B, lz2025)
#   work/vulnscan/apk2025/lz2025_classes2.dex       ( 7870036 B)
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""最小 DEX 解析器 + 字符串邻接/簇分析 —— jadx/GUI 卡死时的替代手段

适用场景
  APK 有加固壳（本次 zxprotect）但业务 dex 是明文 ⇒ 直接从文件里 carve 出 dex，
  然后用本脚本做两件事（都不需要反编译成 Java）：
    ① 字符串表**邻接/簇**分析：DEX 的 string_ids 大致按源码出现顺序排列，
       所以"目标串 ±N 邻居"能直接暴露同一段代码里的参数名/资源名/日志标签。
    ② const-string **引用**分析：定位"哪个类/方法的代码里引用了某个字符串"，
       并 dump 该方法引用到的**全部字符串常量**（≈ 该函数的字面量清单）。

依赖：仅标准库（struct/os/re），无需 jadx / baksmali / 网络。

用法
  python dex_strings.py <a.dex> [b.dex ...]                 # 列字符串表规模
  python dex_strings.py <a.dex> --neigh "/login4" 45        # 打印该串 ±45 邻居（最有用）
  python dex_strings.py <a.dex> --refs "/login4"            # 找引用它的类/方法 + 该方法字面量
  python dex_strings.py <a.dex> --grep "yzm" 40             # 短串正则筛
"""
import struct, os, re, sys


def uleb(d, off):
    r, s, o = 0, 0, off
    while True:
        b = d[o]
        o += 1
        r |= (b & 0x7f) << s
        if not (b & 0x80):
            break
        s += 7
    return r, o


def load(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'dex\n', 'not a dex: ' + path
    ssize, soff = struct.unpack_from('<II', d, 0x38)
    tsize, toff = struct.unpack_from('<II', d, 0x40)
    psize, poff = struct.unpack_from('<II', d, 0x48)
    fsize, foff = struct.unpack_from('<II', d, 0x50)
    msize, moff = struct.unpack_from('<II', d, 0x58)
    csize, coff = struct.unpack_from('<II', d, 0x60)
    strings = []
    for i in range(ssize):
        off = struct.unpack_from('<I', d, soff + 4 * i)[0]
        n, p = uleb(d, off)
        strings.append(d[p:p + n].decode('utf-8', 'replace'))
    types = [strings[struct.unpack_from('<I', d, toff + 4 * i)[0]] for i in range(tsize)]
    methods = []
    for i in range(msize):
        c, pr, nm = struct.unpack_from('<HHI', d, moff + 8 * i)
        methods.append((types[c] if c < len(types) else '?', strings[nm]))
    return d, strings, types, methods, csize, coff


def neighbors(strings, needle, span=45):
    if needle not in strings:
        return None
    i = strings.index(needle)
    lo, hi = max(0, i - span), min(len(strings), i + span + 1)
    return i, [(j, strings[j]) for j in range(lo, hi)]


def refs(d, strings, types, methods, csize, coff, needle):
    """返回 {(class, method): set(引用的字符串)}，只保留引用了 needle 的方法"""
    if needle not in strings:
        return {}
    want = strings.index(needle)
    out = {}
    for ci in range(csize):
        class_idx, _a, _s, _i, _sr, _an, cd, _sv = \
            struct.unpack_from('<8I', d, coff + 32 * ci)
        if not cd:
            continue
        cname = types[class_idx] if class_idx < len(types) else '?'
        o = cd
        sf, o = uleb(d, o)
        inf, o = uleb(d, o)
        dm, o = uleb(d, o)
        vm, o = uleb(d, o)
        for _ in range(sf + inf):
            _, o = uleb(d, o)
            _, o = uleb(d, o)
        for kind in (dm, vm):
            midx = 0
            for _ in range(kind):
                diff, o = uleb(d, o)
                _af, o = uleb(d, o)
                code_off, o = uleb(d, o)
                midx += diff
                if not code_off or midx >= len(methods):
                    continue
                isz = struct.unpack_from('<I', d, code_off + 12)[0]
                ioff = code_off + 16
                end = min(ioff + isz * 2, len(d) - 6)
                lit = set()
                q = ioff
                # 每个 2 字节边界都试（不要跳过，否则会漏）；假阳性由"是否命中目标串"过滤
                while q < end:
                    b0 = d[q]
                    if b0 == 0x1a:      # const-string   vAA, string@BBBB
                        lit.add(struct.unpack_from('<H', d, q + 2)[0])
                    elif b0 == 0x1b:    # const-string/jumbo vAA, string@BBBBBBBB
                        lit.add(struct.unpack_from('<I', d, q + 2)[0])
                    q += 2
                if want in lit:
                    out[(cname, methods[midx][1])] = lit
    return out


def main():
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return
    path = a[0]
    d, strings, types, methods, csize, coff = load(path)
    print('== %s ==\n   strings=%d types=%d methods=%d classes=%d'
          % (os.path.basename(path), len(strings), len(types), len(methods), csize))
    if '--neigh' in a:
        needle = a[a.index('--neigh') + 1]
        span = int(a[a.index('--neigh') + 2]) if len(a) > a.index('--neigh') + 2 else 45
        r = neighbors(strings, needle, span)
        if not r:
            print('  未找到 %r' % needle)
        else:
            i, lst = r
            for j, v in lst:
                if v.strip():
                    print('  %6d %r%s' % (j, v[:150], '   <<<' if j == i else ''))
    if '--refs' in a:
        needle = a[a.index('--refs') + 1]
        hits = refs(d, strings, types, methods, csize, coff, needle)
        print('\n  引用 %r 的方法数：%d' % (needle, len(hits)))
        for (c, m), lit in list(hits.items())[:20]:
            print('\n  === %s -> %s()' % (c, m))
            for s in sorted({strings[i] for i in lit if 0 < i < len(strings)}):
                if 1 <= len(s) <= 90:
                    print('      %r' % s)
    if '--grep' in a:
        pat = re.compile(a[a.index('--grep') + 1])
        lim = int(a[a.index('--grep') + 2]) if len(a) > a.index('--grep') + 2 else 40
        seen = set()
        for i, v in enumerate(strings):
            if 1 <= len(v) <= lim and pat.search(v) and v not in seen:
                seen.add(v)
                print('  %6d %r' % (i, v))


if __name__ == '__main__':
    main()

```
