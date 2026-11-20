# New API / one-api 网关令牌有效性判别法（Invalid token vs User has been banned）

- **code**: new-api-one-api-网关令牌有效性判别法-invalid-token-vs-user-has-been-banned
- **kind**: poc
- **category**: info-leak
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 在 target38.example.com（New API example.com）实测验证：带泄露令牌 sk-hMdKUabqMiRM247Y2b23B02e8f484a9198D27cA2D66eAe4d → HTTP 403 {"error":{"message":"User has been banned"}}；同端点不带 Authorization → HTTP 401 {"error":{"message":"Invalid token"}}。据此判定该令牌真实存在但所属账号已封禁、不可用。
- **path**: pocs/new-api-one-api-网关令牌有效性判别法-invalid-token-vs-user-has-been-banned/newapi-token-validity-probe.http
- **tags**: new-api,one-api,令牌判别,代码泄露,凭据,零爆破
- **created_at**: 2026-09-28T15:43:22.216Z

## 描述

用一个泄露令牌 + 一次只读请求，依据 New API 错误文案区分 Invalid token(401) / User has been banned(403) / 正常(200)，把"令牌是否可用"从猜测变成可证伪的实验；同时不必爆破即可判断泄露物是真实密钥还是占位示例。

## 用法

```
curl -sS -m 25 -w '\nHTTP:%{http_code}\n' -D- \
  -H 'Authorization: Bearer <候选令牌>' \
  'https://<gateway>/v1/models'
随后做一次不带 Authorization 的对照请求。对比两次的状态码与 message 即可定性。
注意：每个凭据最多 2 次尝试、并发 1、串行 ≥1s；不要在真实目标上做字典或批量校验。
```

## 正文

```
原理：New API（Calcium-Ion/new-api）与 one-api 系网关在 token 校验失败时返回的**错误文案可区分两种截然不同的状态**，
因此只要有一个泄露的令牌，就能在不做任何爆破的前提下判断它属于"不存在/伪造"还是"真实但被处置"。

请求模板（只读、无副作用，优先 /v1/models）：
    GET /v1/models HTTP/2
    Host: <gateway>
    Authorization: Bearer <candidate-token>
    Accept: application/json

判读表（2026-09-28 在 New API example.com 实测）：
| 条件 | HTTP | body.message | 结论 |
|---|---|---|---|
| 不带 Authorization（对照组） | 401 | `Invalid token` | 端点正常，基线 |
| 带伪造/不存在的令牌 | 401 | `Invalid token` | 令牌无效 |
| 带真实但被处置的令牌 | **403** | **`User has been banned`** | **令牌真实存在、归属该网关，但账号已被封禁 ⇒ 不可用** |
| 带真实可用令牌 | 200 | 模型列表 JSON | 令牌可用（可直接用于 relay / 作为 SSRF 链的前置"有余额账号"） |

响应头指纹（判定目标是不是 New API 及版本）：
    x-new-api-version: example.com
    x-oneapi-request-id: <request id>
另外 /api/status 未认证即可读（system_name、version、register_enabled、email_verification、turnstile_check），
适合在不带凭据时先确认版本与注册策略。

价值：把"令牌是否可用"从猜测变成可证伪的单次实验，并避免误报——
"有 403 就说明服务端认这个 token"这一点，往往是判断代码泄露物是"真实密钥"还是"占位示例"的决定性依据。

```
