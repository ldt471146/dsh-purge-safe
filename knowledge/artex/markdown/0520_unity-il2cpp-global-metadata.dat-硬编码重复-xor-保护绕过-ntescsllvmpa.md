# Unity IL2CPP global-metadata.dat 硬编码重复 XOR 保护绕过（NTESCSLLVMPASSKEY 案例）

- **code**: unity-il2cpp-global-metadata.dat-硬编码重复-xor-保护绕过-ntescsllvmpa
- **kind**: script
- **category**: info-leak
- **component**: Unity IL2CPP / UnityFramework (iOS)
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在授权目标 inwc.junshengkj.xyz 的第二 iOS 构建 IOSDownload_2/ios.ipa（1.0.0.9）实测：密文 sha256 bc14ad4ad8b314616e4d9913fdff35ad108d90e14ff7a40d61bf5c57dd263621，用 NTESCSLLVMPASSKEY 重复 XOR 后明文 sha256 93c9a048ea3d544c3e572a8c4d0a52011ed8a184daaa1dc07f1644f93391a97c、头 af1bb1fa（magic 0xFAB11BAF, version 29），解析出 19838 类型/164904 方法/94873 字段/23339 字符串字面量；错误密钥对照头为 b61dbbe7 且 mscorlib 零命中。
- **path**: pocs/unity-il2cpp-global-metadata.dat-硬编码重复-xor-保护绕过-ntescsllvmpa/il2cpp_metadata_repeat_xor.py
- **tags**: il2cpp,unity,ios,metadata,xor,obfuscation,reverse
- **created_at**: 2026-11-04T14:37:01.509Z
- **engine**: inwc.junshengkj.xyz/IOSDownload_2/ios.ipa
- **found_by**: exploit

## 描述

某些 Unity IL2CPP 加固产品把 Data/Managed/Metadata/global-metadata.dat 用「固定密钥重复 XOR」加密，密钥以 XOR-with-last-byte 形式藏在 UnityFramework 的 __data，并由 ObjC 方法 [NSData obfuscateXOR:withName:] 调用（metadata 唯一加载路径：字符串 "global-metadata.dat" 的 ADRP 引用 → 解密函数 → obfuscateXOR）。找到密钥后用重复 XOR 即可离线还原明文 metadata（magic 0xFAB11BAF）。

## 用法

```
python il2cpp_metadata_repeat_xor.py；替换 IPA 路径与密钥后运行，输出 global-metadata.dec.dat（magic 0xFAB11BAF）
```

## 正文

```
定位步骤（iOS Mach-O，UnityFramework）：
1) 在 __cstring 找 "global-metadata.dat" 的地址；在 .text 扫描引用该页的 ADRP+ADD（唯一命中处即加载路径）。
2) 顺着加载函数里的 bl 找解密函数；典型实现：18 字节循环 ldrb 从 __data 读取混淆串，再与最后一个字节（常见 0x79）异或，得到 17 字节密钥（本例为 NTESCSLLVMPASSKEY）。
3) 调用链末端是 ObjC 方法 obfuscateXOR:withName:，实现为 data[i] ^= key[j]; j=(j+1)%keylen，key 为 name 的 UTF-8 字节。
4) 离线解密并验证：明文头必须是 AF1BB1FA + version(uint32)，且能解析出 mscorlib/Assembly-CSharp 等字符串；再用一个错误等长密钥做阴性对照。

验证/利用脚本（Python）：
```python
import zipfile, hashlib, struct
IPA = "ios.ipa"; KEY = b"NTESCSLLVMPASSKEY"
z = zipfile.ZipFile(IPA)
raw = z.read("Payload/poker.app/Data/Managed/Metadata/global-metadata.dat")
dec = bytes(c ^ KEY[i % len(KEY)] for i, c in enumerate(raw))
assert struct.unpack_from('<I', dec, 0)[0] == 0xFAB11BAF
open("global-metadata.dec.dat","wb").write(dec)
# 解析头部：v29 起 8+8k 为 (offset,size) 对：k0 stringLiteral, k1 stringLiteralData, k5 methods, k19 typeDefinitions
h = struct.unpack_from('<60I', dec, 0)
print('version', h[1], 'literals', h[3]//8)
```
解析后可得到完整类型/方法/字段名与字符串字面量，并直接喂给 Il2CppDumper（binary 用 UnityFramework，metadata 用解密后的文件）产出 dump.cs。
```
