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