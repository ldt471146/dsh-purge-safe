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