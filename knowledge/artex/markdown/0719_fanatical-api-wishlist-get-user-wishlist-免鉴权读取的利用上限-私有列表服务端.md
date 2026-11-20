# Fanatical /api/wishlist/get-user-wishlist 免鉴权读取的利用上限（私有列表服务端抑制 / sort 副本白名单 / 写面需真实 userId）— 主线无收益，证否原文

- **code**: fanatical-api-wishlist-get-user-wishlist-免鉴权读取的利用上限-私有列表服务端
- **kind**: poc
- **category**: unauthorized
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机 Linux curl 经 CF 公网 www.fanatical.com 实测：①647fa7701774abfaa51d7e74 → 200/82199B（name=Ayamota,nbHits=160）；②私有 62d4643240e4e100967ad292 → 200/40B {"items":[],"err":null,"isPrivate":true}（服务端抑制）；③hitsPerPage=1000 无效仍 36/页，page=999999 → nbHits=0；④sort 仅 fan_price_asc/fan_price_desc/fan_release_date_desc 在错误栈 URL 中命中 /1/indexes/fan_* 副本，fan_users/fan_orders/fan_keys/../fan/query 等全回退 index=fan；⑤POST addtowishlistfromslug 无 userId→400 "No user id"，伪造 userId→400 "email not passed to crm dispatch setWishlist"，未知 slug→404。结论：仅能采集用户主动公开的公开商品数据（76 列表/10,375 项，仅 1 个 gmail 显示名），无礼卡/订单/会话/后台入口。
- **path**: pocs/fanatical-api-wishlist-get-user-wishlist-免鉴权读取的利用上限-私有列表服务端/poc.txt
- **tags**: fanatical,wishlist,unauthorized,利用上限,证否
- **created_at**: 2026-11-11T22:07:38.536Z
- **engine**: https://www.fanatical.com/api/wishlist/get-user-wishlist/{wishlistId}

## 用法

```
复测判据：公开 id 应 200 且含 items；私有 id 应 200 且 items=[]、isPrivate=true（若私有返回 items 则本条否定失效）。想确认索引控制权时用 `sort=<候选>&page=0`，看 err.transporterStackTrace[0].request.url 中的 /1/indexes/<name>/query：只有 fan_price_asc/fan_price_desc/fan_release_date_desc 会变，其余回退 fan。别再尝试 hitsPerPage 放大或私有 id 越权。
```

## 正文

```
## 适用
Fanatical（www.fanatical.com，Cloudflare Worker → Heroku storefront app）的愿望单分享接口 `/api/wishlist/get-user-wishlist/{24hex wishlistId}`。本条目是**已证否的利用上限**，用于阻止后续 worker 重复深挖。

## 判据与实测
1) 无鉴权读取公开列表（真实存在）：
```
curl -s -A "$UA" -H 'accept: application/json' \
 'https://www.fanatical.com/api/wishlist/get-user-wishlist/647fa7701774abfaa51d7e74?sort=fan&page=1'
# 200/82199B {"wishlistDisplayName":"Ayamota","items":[...],"nbHits":160,"nbPages":5,"hitsPerPage":36,"isPrivate":false}
```
2) 私有列表**服务端抑制** items（越权不成立）：
```
.../62d4643240e4e100967ad292?sort=fan&page=1
# 200/40B {"items":[],"err":null,"isPrivate":true}
```
3) 分页不可放大：`hitsPerPage=1000` 被忽略（固定 36/页）；`page=999999` → `{"items":[],"nbHits":0}`。
4) `page=0/-1/0x10` 触发 Algolia ApiError，`err.transporterStackTrace` 回显完整查询体（index=fan、slug filters、facetFilters=["included_regions:US"]、analyticsTags=`amen.WishlistController.getWishlistByWishlistId`、appId=W2M9492DDV、api-key 脱敏 *****）——信息泄露，与公开 key 面同类，无越权。
5) `sort` 控制 Algolia 副本索引名但**白名单**：仅 `fan_price_asc` / `fan_price_desc` / `fan_release_date_desc` 命中 `/1/indexes/fan_*`；`fan_users`/`fan_orders`/`fan_keys`/`fan_redeem_codes`/`fan_wishlists`/`fan_staging_*`/`../fan/query`/`_users` 全部回退 `fan`，不能读非商品索引。
6) 写面：`POST /api/wishlist/addtowishlistfromslug`（JSON）无 userId→400 12B "No user id"；伪造 userId→400 46B "email not passed to crm dispatch setWishlist"（需库内真实 userId 并取到 email 才进 CRM setWishlist）；未知 slug→404；`POST /api/wishlist/save`→400 "Could not parse id"；`PUT /api/user/*wishlist*` 系列→401。

## 批量采集上限
Wayback CDX `/wishlist/{id}` 前缀可得 76 个唯一 id，76/76 匿名 200；75 个具名公开列表 nbHits 合计 10,375（最大 1,103 项，分页 1..28 取回 1,000 个完整商品文档）。字段均为公开商品目录字段（product_id/sku/name/price/fullPrice/discount_percent），显示名 75 个中仅 1 个为 gmail 邮箱。**无礼卡码、序列号、订单、会话、后台入口。**

## 结论
该线索可下沉为低危：仅“用户主动公开分享的愿望单被无鉴权批量采集”。私有列表、越权索引、未授权写均实测否定；不要再沿此端点打礼卡/订单/后台。
```
