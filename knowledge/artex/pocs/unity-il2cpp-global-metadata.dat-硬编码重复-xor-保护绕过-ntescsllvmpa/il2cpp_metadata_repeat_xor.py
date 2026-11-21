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