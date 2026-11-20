# Wix 站点 tag-manager 真实端点发现法：siteTags.bundle → /_api/tag-manager/api/v1/tags/sites/{metaSiteId}（匿名读、三态签名、写不可用）

- **code**: wix-站点-tag-manager-真实端点发现法-sitetags.bundle-_api-tag-manag
- **kind**: script
- **category**: recon
- **component**: Wix Tag Manager (tag-manager-client / siteTags.bundle)
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测（curl + $ARTEX_UA，本机）：站点首页加载 static.parastorage.com/services/tag-manager-client/1.1075.0/siteTags.bundle.min.js，其中硬编码 _api/tag-manager/api/v1/tags/sites/；GET https://www.kennysbuyselltrade.co.uk/_api/tag-manager/api/v1/tags/sites/d6a9751e-7c58-4486-bd67-1a49a529844c?wixSite=true&htmlsiteId=cdbb7abc-9b99-4354-9c00-8d9bfae60166&language=en → 200 application/json 24132B/10 tags（GTM-5FJ83QT8、G-GL0T4V06TE、FB Pixel 674088710567780）；合法 app-instance 令牌 → 24983B/11 tags；篡改签名 → 200 1394B tags=[] errors=[SiteEmbedsServiceError]；POST/PUT/PATCH/DELETE → 200 "OK" 且 GET 前后哈希不变；缺 htmlsiteId → 400 MissingArgumentError；随机 metaSiteId → 200 空 tags。
- **tags**: wix,tag-manager,siteTags.bundle,_api,recon,metaSiteId,app-instance-token
- **created_at**: 2026-11-11T17:47:56.364Z
- **engine**: https://www.kennysbuyselltrade.co.uk
- **found_by**: recon

## 描述

Wix 站点的 tag-manager 前缀 /_api/tag-manager/* 对任意路径返回 200 text/plain "OK"（catch-all），真实 controller 路径不在常规 /v1/<resource> 下。要从站点加载的 tag-manager-client bundle（static.parastorage.com/services/tag-manager-client/<ver>/siteTags.bundle.min.js）grep 出内部路径 `_api/tag-manager/api/v1/tags/sites/`，再用站点 HTML 里的 metaSiteId 调用。返回站点全部 tag（GTM/GA/FB Pixel/第三方 app embed，属公开运行配置，非越权数据）；仅 GET/HEAD（OPTIONS Allow: GET,HEAD），POST/PUT/PATCH/DELETE 走 catch-all OK 且无写效果。三态：无令牌可读基础 tags；任意合法 app-instance 令牌多一个 cookie-banner tag；篡改签名 fail-closed（SiteEmbedsServiceError）。查询键是路径 metaSiteId（随机 GUID 返回空 tags、本站 htmlsiteId 亦 0 tags）——是否可跨站读取需用他站真实 metaSiteId（跨租户，勿默认做）。

## 用法

```
1) 首页 grep "tag-manager-client" → 下载 siteTags.bundle.min.js；grep -o '_api/tag-manager[^"'"'"']*' 得内部路径。
2) 从首页/页面 config 取 metaSiteId（形如 d6a9751e-…）。
3) curl -s -A "$ARTEX_UA" "https://<TARGET>/_api/tag-manager/api/v1/tags/sites/<metaSiteId>?wixSite=true&htmlsiteId=<siteId或任意GUID>&language=en" → 200 JSON tags[]。
4) 三态对照：加 Authorization: <apps['675bbcef-18d8-41f5-800e-131ec9e08762'].instance>（/_api/v1/access-tokens 匿名可取）→ tags+1；篡改签名段末位 → tags=[] + SiteEmbedsServiceError（证明签名被校验）。
5) 写面：POST/PUT/PATCH/DELETE 同路径只回 200 "OK"(2B) catch-all，POST 前后 GET sha1 不变——不要把它当写入口。
```
