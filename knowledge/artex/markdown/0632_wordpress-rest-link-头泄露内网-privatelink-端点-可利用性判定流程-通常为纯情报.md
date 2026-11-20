# WordPress REST Link 头泄露内网 PrivateLink 端点：可利用性判定流程（通常为纯情报）

- **code**: wordpress-rest-link-头泄露内网-privatelink-端点-可利用性判定流程-通常为纯情报
- **kind**: poc
- **category**: info-leak
- **component**: WordPress
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测 www.greenmangaming.com/blog：vpce-0921aaf1...us-east-1.vpce.amazonaws.com 经 8.8.8.8/1.1.1.1 均解析到 10.100.42.47/10.100.59.173；直连 000/6s；Fastly Host vpce 返回 HTTP/2 421；oembed/url-details/loopback/abilities 全 401；dev.topleftdesign.com 全路径 403。事实 id 1959。
- **path**: pocs/wordpress-rest-link-头泄露内网-privatelink-端点-可利用性判定流程-通常为纯情报/poc.md
- **tags**: wordpress,info-leak,privatelink,ssrf,dns,negative
- **created_at**: 2026-11-11T17:55:45.167Z
- **engine**: https://www.greenmangaming.com/blog

## 描述

WP REST API 的 Link 头（rel=https://api.w.org/）与 /wp/v2/users/{id} 的 url 字段会暴露站点 home_url；当站点部署在 AWS 私有子网时，可能泄露 vpce-*.vpce.amazonaws.com 内网端点与外包 dev 域名。判定是否可利用要分四层：DNS 解析、公网路由、边缘 Host/SNI 路由、站内匿名取址端点。大站点常见结局是纯情报型泄露。

## 用法

```
先 nslookup/getent 复核是否解析到 RFC1918；再 curl 直连确认 000；再测 CDN 边缘 Host/SNI（Fastly 421）；最后逐个匿名请求 WP 的 oembed proxy / url-details / loopback / abilities，全 401 即判纯情报。
```

## 正文

```
## 判定清单（按顺序实测）
1) DNS：`getent ahostsv4 <host>` + `nslookup <host> 8.8.8.8/1.1.1.1`。解析到 RFC1918（10.x/172.16-31/192.168）只证明泄露，不证明可达；A 记录存在而 AAAA/zonal 变体可能不同。
2) 公网路由：`curl -m6 http(s)://<ip>/`。私网 IP 从公网出口通常 000/超时（含经记录代理 CONNECT）。
3) 边缘 Host/SNI：对目标前置 CDN 的 IP 做 `curl --resolve <host>:443:<cdn-ip> https://<host>/` 与 `-H "Host: <host>"`。Fastly 会对未匹配证书 SAN 的 Host 返回 HTTP/2 421（"Requested host does not match any Subject Alternative Names"），AWS ALB+Cognito 则可能按 Host 反射生成 redirect_uri（但 Cognito 校验已注册回调，不能换会话）。
4) 站内匿名取址面（WordPress 常见，逐个实测）：
   - `GET /wp-json/oembed/1.0/proxy?url=<url>`（核心；强化站点返回 401 rest_forbidden）
   - `GET /wp-json/wp-block-editor/v1/url-details?url=<url>`（401 rest_cannot_view_url_details）
   - `GET /wp-json/wp-site-health/v1/tests/loopback-requests`（401）
   - `GET /wp-json/wp-abilities/v1/abilities` 与 `/categories`（WP 6.9+，401）
   - `POST /xmlrpc.php` pingback（多数被边缘 403）
   判据：若这些端点对匿名返回 200 且响应/时序随内网 URL 变化，才可能把泄露变成 SSRF 入口；全 401 即无站内取址面。
5) 泄露的外包 dev 域名：单独测其访问控制（多路径含随机不存在路径是否统一 403、XFF/X-Real-IP 伪造是否改变），若全 403 说明 IP 白名单/deny-all，司法外不可直接利用。

## 结论口径
只有“有站内 SSRF 或已拿到目标 VPC 内立足点”时，vpce 泄露才可升级为入口；否则按 info-leak 记录，报告里写清 DNS 可解析 + 四层均不可达的实测证据。
```
