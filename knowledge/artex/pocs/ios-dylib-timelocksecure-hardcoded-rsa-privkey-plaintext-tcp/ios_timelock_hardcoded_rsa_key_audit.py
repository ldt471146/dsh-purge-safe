# iOS 时间锁 SDK 硬编码 RSA 私钥 + 明文 TCP 授权校验（TimeLockSecure 案例）

## 前置条件
- 已授权拿到目标 iOS 分发链的 IPA（本例：`https://inwc.junshengkj.xyz/IOSDownload_2/ios.ipa`，252,202,913B，构建 1.0.0.9）。
- 本地 python3 + `cryptography`；逆向工具（Ghidra/IDA 或 `llvm-objdump --macho -d`）。
- 只对授权范围内的资产操作；不要向第三方 verify 主机发请求。

## 一、样本与静态特征
- dylib：`Payload/poker.app/hhhsd.dylib`，199,056B，SHA256 `4c6257a9db9fecf6e6d17308612c1f6f4199924f5f5ee5b28c40c7cd2077c796`，@rpath `libTimeLockSecure.dylib`。
- Mach-O：magic `cffaedfe`，filetype=6（dylib），`__text` @0x4000 size=0xd490，`__cstring` @0x12960。
- `__cstring` 关键字面量：
  - `0x12e60`：verify 主机名（第三方时间锁服务）
  - `0x12e80`：base64 736 字符 = 4096-bit RSA SPKI 公钥（DER ≈550B）
  - `0x13170`：base64 3168 字符 = PKCS#8 RSA 私钥（DER ≈2374B，base64 以 `MIIJ` 开头）
- 符号表（TimeLockSecure.TLManager 静态属性，vpfi）：`rsaPublicKey` 0x784c / `rsaPrivateKey` 0x7868 / `uuidKeychainService` 0x7834 / `verifyHost` 0x7870 / `verifyPort` 0x788c。
- 实例初始化 0x78a8 写入：`[+0x3a0]`=verifyHost、`[+0x398]`="MYAppID"、`[+0x3a8]`=0x1FA4(8100)、`[+0x3b0]`=737B 公钥字面量、`[+0x3b8]`=3168 字符私钥字面量。
- 建连 0x7f34：`NWEndpoint.Host(verifyHost)` + `NWEndpoint.Port(rawValue: 0x1fa4)` + `NWParameters.tcp` → **明文 TCP，无 TLS 参数、无证书校验符号**。
- 请求侧 0x8528：`cmd=verify` 等字段 → `tlRSAEncrypt`（`SecKeyCreateWithData`@0xb0c4、`SecKeyGetBlockSize`@0xb210、`SecKeyCreateEncryptedData`@0xb35c，日志 "RSA encrypted OK, length="）→ Base64 → "Sending verify request"。
- 响应侧 0xbacc：base64 解码 → `safeRSADecrypt` → `tlRSADecrypt`（`SecKeyCreateWithData`@0xefc4、`SecKeyGetBlockSize`@0xefe8、`SecKeyCreateDecryptedData`@0xf22c）→ JSON（"PARSE S1: RSA decrypt OK"）。

## 二、密钥提取（脚本，输出仅打印指纹，不落密钥原文）
```python
#!/usr/bin/env python3
# key_extract.py <dylib> [--dump out_prefix]
import re, sys, hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

data = open(sys.argv[1], 'rb').read()
blobs = re.findall(rb'[A-Za-z0-9+/]{300,}={0,2}', data)
print('candidates:', [len(b) for b in blobs])
pubs, privs = [], []
for b in blobs:
    raw = b
    try:
        k = serialization.load_der_public_key(__import__('base64').b64decode(raw))
        pubs.append((len(raw), k)); print('SPKI pub ok, base64 len', len(raw), 'bits', k.key_size)
    except Exception:
        pass
    try:
        k = serialization.load_der_private_key(__import__('base64').b64decode(raw), password=None)
        privs.append((len(raw), k)); print('PKCS#8 priv ok, base64 len', len(raw), 'bits', k.key_size)
    except Exception:
        pass

def spki_sha(pub):
    return hashlib.sha256(pub.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
def mod_sha(pub):
    return hashlib.sha256(pub.public_numbers().n.to_bytes(512, 'big')).hexdigest()

print('--- fingerprints (no key material) ---')
for l, k in pubs:  print('pub  b64len=%d bits=%d spki_sha256=%s mod_sha256=%s' % (l, k.key_size, spki_sha(k), mod_sha(k)))
for l, k in privs:
    p = k.public_key()
    print('priv b64len=%d bits=%d der_sha256=%s mod_sha256=%s derived_spki_sha256=%s' % (
        l, k.key_size,
        hashlib.sha256(k.private_bytes(serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())).hexdigest(),
        mod_sha(p), spki_sha(p)))
```

## 三、功能验证（证明私钥真实可用）
```python
#!/usr/bin/env python3
# key_verify.py pub.b64 priv.b64
import base64, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

pub = serialization.load_der_public_key(base64.b64decode(open(sys.argv[1]).read().strip()))
priv = serialization.load_der_private_key(base64.b64decode(open(sys.argv[2]).read().strip()), password=None)
assert priv.key_size == 4096
# 1) 私钥可用：加解密 roundtrip
ct = priv.public_key().encrypt(b'probe', padding.PKCS1v15())
print('roundtrip:', priv.decrypt(ct, padding.PKCS1v15()) == b'probe')
# 2) 签名/验签 OK
sig = priv.sign(b'probe', padding.PKCS1v15(), hashes.SHA256())
priv.public_key().verify(sig, b'probe', padding.PKCS1v15(), hashes.SHA256())
print('sign/verify: True')
# 3) 关键：公钥 A 与私钥 B 是否一对
a = pub.public_numbers().n
b = priv.public_key().public_numbers().n
print('same modulus (a real pair):', a == b)
```

判定要点：
- 公钥 A 加密**请求**（服务端持私钥 A），私钥 B 解密**响应**（服务端用公钥 B 加密）。
- 本例 A/B **模数不同，不是一对**；原"一对公私钥"表述属于误判，但"私钥随客户端分发"这一信任根暴露结论不变。
- 只有"私钥被写入实例字段且被 `SecKeyCreateDecryptedData` 实调"才算成立；仅出现在 `__cstring` 中、无引用者 → 视为残留字符串，降级。

## 四、反汇编判据（三步任一不成立即不能下结论）
1. 解密侧引用私钥字段：`ldr xN, [xN, #0x3b8]` → `SecKeyCreateWithData` → `SecKeyCreateDecryptedData`。
2. 加密侧引用公钥字段：`ldr xN, [xN, #0x3b0]` → `SecKeyCreateEncryptedData`。
3. 通道为明文：`NWParameters.tcp`（或 `NSStream`/`CFStream` 直连），全调用链无 `NWProtocolTLS` / `sec_protocol_options` / `SecTrustEvaluate` / `SslStream`。

## 五、复用面扫描
对同任务其它构建/IPA/APK 提取同前缀 base64 检索（`grep -a 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A'`、`grep -a 'MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCS'`），本例仅 IOSDownload_2 的该 dylib 命中，IOSDownload_1 的 IPA、APK、classes*.dex、libil2cpp.so 均为零命中 ⇒ 未跨构建复用。

## 六、影响与边界
- 客户端侧成立：私钥随 App 分发 ⇒ 任何人可离线取得信任根，推导对应公钥后可**解密**服务端 verify 响应；在处于 App→verifyHost:port 的中间位置时，可用明文 TCP **伪造**"授权有效"响应，绕过第三方时间锁与完整性保护（响应 JSON 含设备 UUID 等标识）。
- 服务端侧：不构成本任务目标资产的权限/数据影响；无可复用的 in-scope 消费方。风险主体是 SDK 厂商与客户端授权体系。
- 不做的事：不向域外 verify 主机发请求、不真机装包、不动态伪造服务端（除非另有授权与设备）。

## 七、修复建议
- 立即吊销并更换该 RSA 密钥；客户端不得持有用于解密服务端响应的私钥。
- 校验通道改 TLS + 证书钉扎；响应真实性用服务端签名，客户端只存**公钥**并 `SecKeyVerifySignature`。
- 服务端做设备绑定与重放防护（nonce + 时间窗）。
