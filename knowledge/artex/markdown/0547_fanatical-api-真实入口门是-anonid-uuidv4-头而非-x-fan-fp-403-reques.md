# Fanatical /api 真实入口门是 anonid(UUIDv4) 头而非 x-fan-fp；403 Request blocked 实为 User-Agent 爬虫拦截

- **code**: fanatical-api-真实入口门是-anonid-uuidv4-头而非-x-fan-fp-403-reques
- **kind**: poc
- **category**: recon
- **component**: Fanatical (fanatical.com) Cloudflare Worker + Heroku/Express 后端
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 15:xx UTC 本机 curl 于 www.fanatical.com 实测：GET /api/products/fan/{slug} 用 -A curl/8.5.0 → 403 15B «Request blocked»；改用 Chrome UA（$ARTEX_UA）→ 404 {"message":"Not Found"}（到后端）。GET /api/basket anonid=not-a-uuid → 400 {"err":"AnonId Header not valid"}；anonid=<随机UUIDv4> → 200。x-fan-fp 加 zzz/随机32hex 结果不变。
- **created_at**: 2026-11-11T15:10:27.378Z
- **engine**: https://www.fanatical.com

## 描述

纠正 fact 518 的误判：缺 x-fan-fp 得到 403「Request blocked」不是指纹门，而是 Cloudflare 对 curl/非浏览器 UA 的爬虫拦截；x-fan-fp（@thumbmarkjs/thumbmarkjs 生成的浏览器指纹）在服务端不做值校验，伪造/省略均无差别。真正的「门」是 anonid 头（后端 Express 校验其必须为合法 UUIDv4）。解锁 /api 只需：浏览器类 UA + 任意合法 UUIDv4 anonid，二者均可离线生成，无需真实浏览器指纹。

## 用法

```
UA="$ARTEX_UA"; ANON=$(cat /proc/sys/kernel/random/uuid)
# 门在 UA（403=爬虫拦截）与 anonid（UUIDv4 格式）
curl -sk -A curl/8.5.0  "https://www.fanatical.com/api/products/fan/<slug>"           # -> 403 "Request blocked"
curl -sk -A "$UA" -H "anonid: $ANON" "https://www.fanatical.com/api/products/fan/<slug>" # -> 后端响应(404/200)
curl -sk -A "$UA" -H "anonid: $ANON" "https://www.fanatical.com/api/basket"           # -> 200 该 anonid 的购物车
curl -sk -A "$UA" -H "anonid: not-a-uuid" "https://www.fanatical.com/api/basket"       # -> 400 {"err":"AnonId Header not valid"}
# 负面对照: anonid=->400 AnonId Header not set；x-fan-fp 任意值均无影响
# 注: /api/redeem-code/search 与 /api/redeem-code/get-featured-data/{slug} 另受路径级 429 限流, 本轮未取得分级 oracle
```
