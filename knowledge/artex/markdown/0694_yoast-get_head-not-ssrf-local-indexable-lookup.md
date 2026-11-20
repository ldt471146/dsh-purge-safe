# Yoast SEO get_head 不是 SSRF：for_url 仅按 host 查本地 indexable，端口/query 被丢弃（negative 判据）

- **code**: yoast-get_head-not-ssrf-local-indexable-lookup
- **kind**: poc
- **category**: ssrf
- **component**: Yoast SEO 28.7 (WordPress plugin)
- **severity**: info
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 在 www.greenmangaming.com/blog（Yoast SEO v28.7）实测：url=http://vpce-...:1/ 与 :65535/ 均 200/3694B 同 head（关闭端口仍成功=无 TCP）；url=https://example.com/ 与 169.254.169.254 均 0.4-0.5s 返回本站 404；webhook.site OOB total=0；plugins.svn.wordpress.org/wordpress-seo/tags/28.7 源码 Meta_Surface::for_url（src/surfaces/meta-surface.php:309-335）仅 host 校验+find_by_permalink 本地查库，无 wp_remote_get/wp_safe_remote_get
- **created_at**: 2026-11-11T21:15:31.772Z
- **engine**: https://www.greenmangaming.com/blog/wp-json/yoast/v1/get_head

## 描述

Yoast SEO 的 REST 路由 yoast/v1/get_head?url= 外观像 URL 取址器，实际是本地 indexable 查询：get_head → Indexable_Head_Action::for_url → Meta_Surface::for_url。后者要求 url host === site_url host，重建 URL 时丢弃 port 与 query，再 find_by_permalink 查 wp_yoast_indexable 表渲染 head；无任何出站 HTTP。判据：用必然关闭端口（:1/:65535）仍返回与 :8080 相同的 200 head、外部站点与 169.254 只返回本站 404、OOB webhook 零回连，即可证伪 SSRF。别把「无端口 URL 命中 home_page 分支」与「带端口 URL 走查库分支」的 title 差异误读为端口差异。

## 用法

```
验证步骤：① 对 get_head 传 url=http://<home主机名>:1/ 与 :65535/，若返回与 :8080 相同 head → 端口被丢弃、无连接；② 传 https://example.com/ 与 http://169.254.169.254/，若返回目标站自己的 404 页而非远端内容 → 未发起请求；③ 用 webhook.site 令牌 URL 做 OOB，requests total=0 → 零回连；④ 对照插件源码 src/surfaces/meta-surface.php::for_url 确认仅 find_by_permalink 本地查询。四项齐即可判该端点非 SSRF。
```
