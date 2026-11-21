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
