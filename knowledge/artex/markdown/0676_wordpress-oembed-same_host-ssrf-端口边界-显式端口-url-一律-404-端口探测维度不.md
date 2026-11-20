# WordPress oEmbed same_host SSRF 端口边界：显式端口 URL 一律 404，端口探测维度不可用（含 localhost 与非 REST sink 阴性）

- **code**: wordpress-oembed-same_host-ssrf-端口边界-显式端口-url-一律-404-端口探测维度不
- **kind**: payload
- **category**: ssrf
- **component**: WordPress (core REST oEmbed)
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 对 https://www.greenmangaming.com/blog/wp-json/oembed/1.0/embed 实测：url=http://vpce-.../<slug>/ → 200/3064B（3 次）；同 slug 加 :80 → 404/73B（2/2）；https://vpce-...:443/<slug>/ → 404/73B；:8080 短名单全部 404/73B；localhost/127.0.0.1 全 404；wp-trackback 三组 URL 响应逐字节相同 404/135B；wp-cron 200/0B。
- **path**: pocs/wordpress-oembed-same_host-ssrf-端口边界-显式端口-url-一律-404-端口探测维度不/poc.txt
- **tags**: oembed,ssrf,negative,port-boundary,wordpress
- **created_at**: 2026-11-11T20:28:36.923Z
- **engine**: https://www.greenmangaming.com/blog/wp-json/oembed/1.0/embed

## 描述

WordPress oEmbed same_host SSRF 的能力边界：端口维度在"home 无端口"配置下整体失效；localhost 与四个非 REST sink 均阴性。用于避免把 :8080 等的 404 误读成端口状态。

## 正文

```
结论（2026-11-11 实测，greenmangaming.com /blog）：

1) 端口维度不可用：当 WP 的 home=get_option('home') 被配置为「无端口的内部主机名」时（如 http://vpce-xxx.vpce.amazonaws.com），oEmbed /wp-json/oembed/1.0/embed 的取址只对「无端口形式的同一 host」返回 200。
   - GET /blog/wp-json/oembed/1.0/embed?url=http://<home-host>/<article-slug>/  → 200 / 3064B oEmbed JSON（3 次复现）
   - 同一 slug + 显式 :80  → 404 / 73B {"code":"oembed_invalid_url"}
   - https://<home-host>:443/... → 404 / 73B
   - http://<home-host>:8080/... → 404 / 73B
   即显式端口（即使等于默认端口）本身就会让 URL 不再 same_host → 落回 wp_http_validate_url 的私网/IP 校验 → 被拒。因此不能用 200-vs-404 差分判任何端口（80/443/8080/6379/9010…）是否开放。此前"某端口快速 404 说明端口有服务/端口被拒"的推断全部不可靠。

2) localhost 面：http://localhost/<slug>/（默认 80）、http://localhost/、http://localhost:80|8080/...、http://127.0.0.1/<slug>/ 全部 404/73B，无稳定耗时差分 → localhost 不能作为端口探测/内网跳板。

3) 路径面：源站根路径就是 WP；'/blog' 是 Fastly 边缘前缀（转发时剥掉）。所以 http://<home-host>/<slug>/ = 200，而 http://<home-host>/blog/<slug>/ = 404。只有「返回带 oEmbed <link rel="alternate" type="application/json+oembed"> 的 HTML 页面」才能让 embed 返回 200（公开文章、?s=搜索页可；?p=/?page_id=/author/feed 不行）。

4) 非 REST sink 全不取址（同站实测）：wp-trackback.php POST 的 url 参数不发起请求（三组内网/公网 URL 响应逐字节相同的 135B XML 错误）；wp-comments-post.php 无效 post 200/0B；wp-cron.php 200/0B；admin-ajax.php 被边缘 403/落 WP 404 不可达；xmlrpc.php 被 Apache 直接 403（pingback 信道死）。

5) 附带：/blog/xmlrpc.php 的 Apache 默认 403 页会用 <address> 回显内部 ServerName（生产为 vpce-...amazonaws.com）与 Port 8080，可作内部拓扑泄露的入口之一。

判读建议：拿到 WordPress oEmbed same_host SSRF 后，先确认 home 是否带端口；端口探测/内网横向不要在这条链上投入，除非找到能改写 home 端口或使用 wp_remote_get（非 safe）的插件端点。
```
