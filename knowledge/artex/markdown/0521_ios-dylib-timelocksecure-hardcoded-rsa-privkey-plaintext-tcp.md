# iOS 第三方时间锁 SDK（TimeLockSecure dylib）硬编码 4096-bit RSA 私钥 + 明文 TCP 授权校验 → 客户端保护可离线绕过

- **code**: ios-dylib-timelocksecure-hardcoded-rsa-privkey-plaintext-tcp
- **kind**: script
- **category**: info-leak
- **component**: TimeLockSecure（libTimeLockSecure.dylib，第三方时间锁/授权 SDK）
- **versions**: iOS 构建 1.0.0.9（dylib 199,056B，SHA256 4C6257A9DB9FECF6E6D17308612C1F6F4199924F5F5EE5B28C40C7CD2077C796）
- **severity**: medium
- **language**: python
- **source**: manual
- **verified**: 1
- **verified_note**: task#614（2026-11-04）离线静态验证：从授权分发域 inwc.junshengkj.xyz 免鉴权下载 IOSDownload_2/ios.ipa（252,202,913B，1.0.0.9），解包 Payload/poker.app/hhhhsd.dylib（SHA256 4c6257a9…c796）。__cstring 内定位两条长 base64（@0x12e80 736 字符 = 4096-bit SPKI 公钥；@0x13170 3168 字符 = PKCS#8 RSA 私钥），用 cryptography.load_der_private_key 成功解析为 4096-bit RSA，私钥 encrypt/decrypt roundtrip 与 sign/派生公钥 verify 均 OK；反汇编确认 0xaca8 读实例字段 [+]0x3b0(rsaPublicKey)→SecKeyCreateEncryptedData，0xc03c 读 [+]0x3b8(rsaPrivateKey)→SecKeyCreateDecryptedData，通道为 NWParameters.tcp（0x7f34，无 TLS）；0x78a8 写入 verifyHost=dylib.heima911.com、"MYAppID"、port 8100。附加纠正：公钥 A 与私钥 B 模数不同（不是一对），但私钥确实随包分发并实调。未向域外 verify 主机发请求、未真机动态伪造。
- **path**: pocs/ios-dylib-timelocksecure-hardcoded-rsa-privkey-plaintext-tcp/ios_timelock_hardcoded_rsa_key_audit.py
- **tags**: ios,ipa,dylib,硬编码私钥,rsa,4096,credential-leak,静态逆向,明文tcp,时间锁,授权绕过,app-audit
- **created_at**: 2026-11-04T14:38:37.010Z
- **engine**: https://inwc.junshengkj.xyz/IOSDownload_2/ios.ipa
- **found_by**: internal

## 描述

iOS 客户端内第三方时间锁/授权 SDK（TimeLockSecure）把用于解密服务端 verify 响应的 4096-bit RSA 私钥以 base64 字面量写死在 __cstring，并随 IPA 分发；授权校验走裸 TCP（无 TLS、无证书校验）。任何人解包 IPA 即可取得该私钥（信任根），离线解密甚至伪造"授权有效"响应，绕过厂商时间锁/完整性保护。纯客户端侧问题，通常不转化为目标服务器权限；风险主体是 SDK 厂商与客户端授权体系。

## 用法

```
① 取样本（无需鉴权，Range 取单 entry 避免全量下载）：
  curl -k -sS -H 'Range: bytes=0-' -o ios.ipa https://<分发域>/IOSDownload_2/ios.ipa
  unzip -l ios.ipa | grep -i '\.app/.*\.dylib'
② 提取 __cstring 长 base64（勿把密钥写进报告/库）：
  python key_extract.py <dylib>            # 见 content
  判据：命中 736 字符（SPKI 公钥）与 3168 字符（PKCS#8 私钥，base64 以 MIIJ 开头 ≈2374B DER）。
③ 功能验证（证明私钥真实可用，而不只是字符串）：
  python key_verify.py pub.b64 priv.b64
  期望：load_der_private_key → 4096-bit、e=65537；encrypt/decrypt roundtrip True；sign 后用派生公钥 verify True。
  注意：不要假定公钥/私钥是一对——比对两把模数 SHA256，不一致说明是"公钥 A 加密请求 / 私钥 B 解密响应"的双密钥设计（本例即如此）。
④ 反汇编核对调用方向（objdump -d --macho 或 IDA/Ghidra）：
  - 配置构造处写入 verifyHost / verifyPort(0x1fa4=8100) / uuidKeychainService("MYAppID")
  - 加密侧读 rsaPublicKey 字段并调 SecKeyCreateEncryptedData（请求）
  - 解密侧读 rsaPrivateKey 字段并调 SecKeyCreateDecryptedData（响应）
  - 建连处 NWEndpoint.Host(verifyHost)+NWParameters.tcp，无 tls / NWProtocolTLS / SecTrust 符号 ⇒ 明文
⑤ 复用面扫描：对同任务其它 IPA/APK（其他 IOSDownload_N、classes*.dex、libil2cpp.so）grep 同一 base64 前缀，判断是否跨构建复用。
⑥ 影响判定：私钥随包分发 + 明文 TCP ⇒ 授权校验信任根在客户端；可利用路径是 App→verifyHost:port 的中间位置，用私钥伪造 verify 响应（需用户侧设备 + 网络中间位置）。若私钥仅残留未实调、或 verify 最终判定另有服务端不可伪造锚点（如客户端只存公钥 + 强制 SecKeyVerifySignature），则本结论下调为 informational。
常见失败原因：长 base64 被换行截断（正则用 [A-Za-z0-9+/]{300,}={0,2} 并跨段落拼接）；ipa 为 zip64/大文件导致 unzip 失败（改用 python zipfile 流式读取单 entry）；dylib 为 fat 二进制（先 lipo/按 fat_arch 选 arm64 切片再解 objdump）；把公钥当私钥解析会报"Invalid key"。
```

## 正文

```
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

```
