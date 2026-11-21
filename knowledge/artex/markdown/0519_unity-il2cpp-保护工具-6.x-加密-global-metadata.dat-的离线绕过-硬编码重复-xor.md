# Unity IL2CPP 保护工具(6.x)加密 global-metadata.dat 的离线绕过：硬编码重复 XOR 密钥静态还原 + 完整元数据解密

- **code**: unity-il2cpp-保护工具-6.x-加密-global-metadata.dat-的离线绕过-硬编码重复-xor
- **kind**: script
- **category**: frontend-reverse
- **component**: Unity IL2CPP / iOS IPA（UnityFramework）metadata 保护工具 tool_version 6.4.2
- **versions**: IL2CPP metadata version 29；保护工具 6.x（本例 6.4.2）
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: task#614（2026-11-04）离线静态验证，纯只读无服务端请求：目标 iOS 构建的 Data/Managed/Metadata/global-metadata.dat（19,300,828B，头 e14ff4a9…，全文件无明文符号）；静态定位到 metadata 唯一加载路径与 ObjC 解密方法 obfuscateXOR:withName:（IMP 0x19c693c）；从 __data 混淆串 372d3c2a3a2a35352f3429382a2a323c2079（XOR 末字节 0x79）还原出 17 字节密钥 NTESCSLLVMPASSKEY；用该密钥逐字节循环异或后得到明文头 af1bb1fa 1d000000（magic 0xFAB11BAF、version 29），并在明文中命中 UnityEngine/mscorlib/Assembly-CSharp/handCards/secretKey 等符号；SHA256 93C9A048EA3D544C3E572A8C4D0A52011ED8A184DAAA1DC07F1644F93391A97C。阴性对照：换成等长错误密钥 WRONGKEY0123456789 后头为 b61dbbe719180915、mscorlib 零命中，排除「只去文件头」误判。
- **path**: pocs/unity-il2cpp-保护工具-6.x-加密-global-metadata.dat-的离线绕过-硬编码重复-xor/il2cpp_meta_decrypt.py
- **tags**: il2cpp,unity,ios,ipa,global-metadata,metadata-decrypt,xor,obfuscateXOR,保护绕过,离线逆向,il2cppdumper
- **created_at**: 2026-11-04T14:36:36.731Z
- **engine**: www.winners.club（iOS 客户端 IPA，Data/Managed/Metadata/global-metadata.dat）
- **found_by**: internal

## 描述

针对 Unity IL2CPP 保护工具（tool_version 6.x）加密的 global-metadata.dat：其"加密"实为固定密钥的重复 XOR，密钥以「与最后一字节异或」的混淆形式硬编码在二进制 __data 段，且解密例程就挂在 metadata 唯一加载链上。因此无需运行设备、无需服务端秘密，解包 IPA + 静态定位即可离线还原完整元数据（类型/方法/字段/字符串字面量全部明文），再用 Il2CppDumper 还原符号与逻辑。适用面：任何用同类商业保护器加固的 Unity iOS/Android 包；判据为 metadata 头非 0xFAB11BAF 但文件里存在 ldrb/eor/strb 形式的短串还原循环。

## 用法

```
前置：已获授权拿到 IPA/APK，能解包；python3（可选 pip install pycryptodome 非必需、Il2CppDumper 用于后续符号还原）。

① 取样本并判是否加密
  unzip ios.ipa -d ipa/
  M=ipa/Payload/*.app/Data/Managed/Metadata/global-metadata.dat
  xxd -l 16 "$M"     # 明文应为 af1bb1fa（小端 magic 0xFAB11BAF）；非该值 = 被加密

② 定位加载路径与解密例程（静态，静态分析器/objdump 均可）
  - 在 UnityFramework 的 __cstring 中找 "global-metadata.dat"，记其虚拟地址；
  - 在 .text / il2cpp 段扫描 ADRP 指向该地址所在 4KB 页 + ADD #页内偏移 的引用，取唯一命中（其后紧跟 bl 到 metadata 初始化函数）；
  - 顺加载链往下跟，找到实际做变换的函数。本例是 ObjC 方法 obfuscateXOR:withName:：实现为 data[i] ^= key[j]，j 按 key 长度归零，返回新 NSData。
  - 注意：iOS 上 metadata 由 UnityFramework（而非主二进制）加载，段基址要按 Mach-O __TEXT vmaddr 对齐，ADRP 页基址 4KB 对齐——算错会扫不到唯一引用。

③ 还原密钥（关键：密钥不是固定长度，j 到 keylen 归零）
  - 解密例程里的密钥参数来自一个短的混淆串：18 字节循环 ldrb key,[...+0x11] / ldrb c,[+i] / eor / strb，即每个字节与最后一字节异或。
  - 本例 __data 原始字节 372d3c2a3a2a35352f3429382a2a323c2079，末字节 0x79，异或后为 "NTESCSLLVMPASSKEY"（17 字节，第 18 字节解出 0x00 作填充）。
  - 通用还原：blob = bytes.fromhex("..."); key = bytes(b ^ blob[-1] for b in blob)[:17]

④ 离线解密（脚本见正文）：
  python il2cpp_meta_decrypt.py "$M" global-metadata.dec.dat
  # 或指定密钥： python il2cpp_meta_decrypt.py "$M" out.dat NTESCSLLVMPASSKEY

⑤ 判据（三条全过才算成立）
  - 明文头 magic 0xFAB11BAF（小端 af1bb1fa）+ 合理 version（本例 29）；
  - 明文里 grep 到 mscorlib / System.Private.CoreLib / Assembly-CSharp / UnityEngine 等已知符号；
  - 阴性对照：换等长错误密钥，头部变成乱值且上述符号零命中（排除"只去文件头"的假象）。

⑥ 下一步：Il2CppDumper 用解密后的 metadata + 目标二进制（global-metadata.dat 直接替换或指定路径）导出 dump.cs、DummyDll、stringliteral.json，进入业务逻辑/热更链分析。

失败常见原因：用了主二进制而不是 UnityFramework 的 metadata 路径；ADRP 页基址算错导致没找到唯一引用；把密钥当成 MD5/AES 去猜（实际是任意长度重复 XOR）；密钥模长搞错（j 必须按 keylen 归零，不是固定 16/32）。
```

## 正文

```
# il2cpp_meta_decrypt.py —— Unity IL2CPP 保护工具(6.x)加密 metadata 的离线解密
# 用法:
#   python il2cpp_meta_decrypt.py <encrypted_global-metadata.dat> <out.dat> [key]
#   key 省略时用默认还原出的密钥（从二进制静态还原，见 README/正文步骤 ③）
import sys, hashlib, pathlib

KEY = b"NTESCSLLVMPASSKEY"   # 17 字节，固定重复 XOR

def decrypt(data: bytes, key: bytes) -> bytes:
    """data[i] ^= key[j]，j 按 key 长度归零（与 ObjC obfuscateXOR:withName: 一致）"""
    if not key:
        raise ValueError("empty key")
    klen, k = len(key), key
    return bytes(b ^ k[i % klen] for i, b in enumerate(data))

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    src, dst = sys.argv[1], sys.argv[2]
    key = sys.argv[3].encode() if len(sys.argv) > 3 else KEY

    raw = pathlib.Path(src).read_bytes()
    out = decrypt(raw, key)
    pathlib.Path(dst).write_bytes(out)

    magic   = int.from_bytes(out[0:4],  "little")
    version = int.from_bytes(out[4:8],  "little")
    print("in : %s (%d bytes)" % (src, len(raw)))
    print("out: %s (%d bytes)" % (dst, len(out)))
    print("magic=0x%08X version=%d sha256=%s" % (magic, version, sha256_hex(out)))

    if out[:4] != b"\xaf\x1b\xb1\xfa":
        print("[!] magic != 0xFAB11BAF —— 密钥错误，或该文件不是本保护格式")
        sys.exit(2)
    for s in (b"mscorlib", b"Assembly-CSharp", b"UnityEngine"):
        print("  %-16s hits=%d" % (s.decode(), out.count(s)))

if __name__ == "__main__":
    main()


# ---------------------------------------------------------------
# 附：从二进制 __data 段还原密钥（混淆方式 = 每字节 XOR 最后一字节）
# blob = bytes.fromhex("372d3c2a3a2a35352f3429382a2a323c2079")   # 本例原始字节
# key  = bytes(b ^ blob[-1] for b in blob)[:17]                 # -> b"NTESCSLLVMPASSKEY"
#
# 附：阴性对照（必须做，用于排除“只去文件头”的误判）
#   python il2cpp_meta_decrypt.py meta.dat bad.dat WRONGKEY0123456789
#   -> magic 乱值（本例 0x19e7bb1d）、mscorlib hits=0
#
# 附：定位要点（iOS）
#   1) xcrun nm / objdump -d Payload/<app>.app/Frameworks/UnityFramework.framework/UnityFramework
#   2) __cstring 中 "global-metadata.dat" 的虚拟地址 -> 4KB 页内偏移
#   3) .text 段扫 ADRP page + ADD #offset 的唯一命中，其后 bl 即 metadata 初始化函数
#   4) 初始化函数再 bl 到解密例程；本例为 ObjC 方法 obfuscateXOR:withName:
#      (__objc_const 方法表项 types '@32@0:8@16@24'，IMP 0x19c693c)
#   5) 解密例程内部用短循环 ldrb/eor/strb 从 __data 还原密钥串

```
