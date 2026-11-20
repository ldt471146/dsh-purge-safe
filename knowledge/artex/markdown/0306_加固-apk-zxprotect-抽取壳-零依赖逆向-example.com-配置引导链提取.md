# 加固 APK（zxprotect 抽取壳）零依赖逆向 + example.com 配置引导链提取

- **code**: 加固-apk-zxprotect-抽取壳-零依赖逆向-example.com-配置引导链提取
- **kind**: script
- **category**: info-leak
- **component**: 加固 APK（zxprotect 抽取壳）+ 站群 App 配置引导链
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（example.com「掌上码表」, marksix 六合彩类）上实测：① 判壳成立（declared strings=162/classes=6 vs filesize 11,805,553）；② 切出 c01.dex(0x25c8, 3173588B, 25158 strings/2428 classes) 与 c02.dex(0x3092c8, 8622108B, 52177 strings/8477 classes)，两者 SHA1 签名校验均通过；③ 提取 129,923 条字符串，抠出 API 基址 https://example.com / https://example.com、服务前缀正则 (/(LHService|Tk_Kj|IMService)/v27/[a-z/]+、60+ 条接口路径、加密算法 AES-256-GCM+RSA-SHA256、请求头 X-Device-Signature/X-Nonce/X-Timestamp、支付 http://203.0.113.40:8080/PayBmob；④ example.com 三镜像 200 且内容一致（MD5 CFD183A3E0921085C8F581E4501C93DF）。反编译覆盖度：c01 可解 7738/15091、c02 可解 29566/49239 方法；App 自身业务类仅 39 个方法带字符串、0 条 URL 常量 ⇒ 业务密钥/签名代码被壳保护，静态不可读（如实记录）。
- **path**: pocs/加固-apk-zxprotect-抽取壳-零依赖逆向-config2.json-配置引导链提取/poc.py
- **tags**: android,apk,加固,抽取壳,zxprotect,dex切分,config引导链,C段指纹比对,信息收集
- **created_at**: 2026-10-11T07:00:23.718Z

## 描述

抽取壳（zxprotect）APK 的零依赖逆向套路：先判壳，再按 dex 魔数切出内嵌有效 dex，用全量字符串表绕过被加密的字节码，从字符串表取 API 基址/服务前缀正则/路径清单/example.com 镜像链，最后用 ProxyHandler({}) 拉取 AES-256-GCM 加密的后端路由配置。附带"同 C 段响应指纹比对"找隐藏节点的做法。

## 用法

```
把 example.com 放当前目录后 python apk_hardened_recon.py。关键点：① 先比 header 声明量（string_ids_size/class_defs_size）与文件体积判断是否加固；② 用正则 rb"dex\\n0[0-9]{2}\\x00" 扫全文件找所有 dex 魔数，按 header.file_size 切出并校验 SHA1（本站切出 2 个有效内嵌 dex：c01 2428 类 / c02 8477 类）；③ 字节码被加密（androguard 报 InvalidInstruction 0xfd/0xed）时不要死磕反编译，改用全量字符串表；④ 拉配置必须 ProxyHandler({}) 禁系统代理。另附 C 段隐藏节点发现法：对整段逐 IP 请求已知业务路径，按响应指纹（错误体/框架特征）归类。
```

## 正文

```
#!/usr/bin/env python3
# 加固 APK 零依赖逆向 + 配置引导链拉取（适用于 libzxprotect.so / 随机名 so 的抽取壳 APK）
import re, struct, zipfile, os

APK = r"example.com"
# ① 解包
zipfile.ZipFile(APK).extractall("apk")
d = open("apk/classes.dex", "rb").read()

# ② 判壳：头部声明量 vs 文件体积
strsz   = struct.unpack_from("<I", d, 0x38)[0]   # string_ids_size
clsz    = struct.unpack_from("<I", d, 0x60)[0]   # class_defs_size
print("declared strings=%d classes=%d filesize=%d" % (strsz, clsz, len(d)))
# 例：declared strings=162 classes=6 filesize=11805553  ⇒ 加固（容器）

# ③ 切出所有内嵌 dex（关键：魔数可能在文件任意偏移；用 header.file_size 切）
for m in re.finditer(rb"dex\n0[0-9]{2}\x00", d):
    o = m.start()
    if o + 0x70 > len(d): continue
    fs = struct.unpack_from("<I", d, o + 0x20)[0]
    s  = struct.unpack_from("<I", d, o + 0x38)[0]
    c  = struct.unpack_from("<I", d, o + 0x60)[0]
    print("dex @0x%x size=%d strings=%d classes=%d" % (o, fs, s, c))
    if 0 < fs <= len(d) - o:
        blob = d[o:o + fs]
        import hashlib
        assert blob[12:32] == hashlib.sha1(blob[32:]).digest(), "sig mismatch"
        open("carved_%x.dex" % o, "wb").write(blob)   # SHA1 通过 ⇒ 有效 dex

# ④ 全量字符串（不依赖 androguard，绕过字节码被加密）
S = set()
for pat in (rb"[\x20-\x7e]{4,400}", rb"(?:[\x20-\x7e]|[\xc2-\xf4][\x80-\xbf]+){4,400}"):
    for m in re.finditer(pat, d):
        try: S.add(target22.example.com().decode("utf-8"))
        except Exception: S.add(target22.example.com().decode("latin1"))
open("dex_strings.txt", "w", encoding="utf-8").write("\n".join(sorted(S)))

# ⑤ 找配置引导链：App 的 example.com 镜像（本站群固定 4 源）
for s in S:
    if "example.com" in s: print("CONFIG SRC:", s)
# 本站实测输出：
#   http://203.0.113.5/routing-v27/example.com          (已废弃 404)
#   https://example.com/routing-v27/example.com    (200)
#   https://target321.example.com/routing-v27/example.com (200)
#   https://6z-1251023784.cos.ap-guangzhou.myqcloud.com/routing-v27/example.com (200)

# ⑥ 找服务前缀正则与路径（路径全在字符串表里，可靠）
for s in S:
    if re.search(r"/(LHService|Tk_Kj|IMService)/v27/", s) or re.match(r"^[a-z][a-z0-9_\-]{1,24}(/[a-z0-9_\-{}.:]{1,40}){1,6}$", s):
        print("PATH:", s)

# ⑦ 拉取加密配置（App 自己拉的公开文件）
import urllib.request
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # 本机系统代理会劫持，必须显式禁用
r = op.open("https://example.com/routing-v27/example.com", timeout=25)
print(r.read().decode())
# {"schema":1,"keyId":"prod-routing-20260922","version":4,"issuedAt":1791055280508,
#  "expiresAt":1791660080508,"algorithm":"AES-256-GCM+RSA-SHA256",
#  "iv":"9q6Vt7qQqTuKMdsg","ciphertext":"...","signature":"..."}
# ⇒ GCM 12 字节 IV 的 base64；keyId 指明密钥版本；解密需 App 内硬编码 AES-256 key
#    （本站 key 位于被抽取加密的业务代码里，静态不可读，需脱壳）

```
